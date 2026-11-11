#!/usr/bin/env python3
"""Qoder CN 多账号签到。Python 3.9+，仅使用标准库。

API 协议参考 88lin/workbuddy-auto-signin (MIT)，详见 THIRD_PARTY.md。
"""
import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import getpass
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

if os.name == "nt":
    import msvcrt
else:
    import fcntl

BASE_URL = "https://openapi.qoder.com.cn"
CN = timezone(timedelta(hours=8))
DEFAULT_CONFIG = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "qoder-signin/accounts.json"
SUCCESS = {"CLAIMED", "ALREADY", "INACTIVE", "DRY_RUN", "OK"}


class ConfigError(Exception):
    pass


class ApiError(Exception):
    def __init__(self, result, message):
        self.result = result
        super().__init__(message)


class BusyError(Exception):
    pass


def clean_token(value):
    if not isinstance(value, str):
        raise ConfigError("token 必须为字符串")
    value = value.strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,32768}", value):
        raise ConfigError("token 为空或包含非法字符")
    return value


def read_config(path):
    try:
        mode = path.stat().st_mode
        if os.name != "nt" and stat.S_IMODE(mode) & 0o077:
            raise ConfigError("配置文件权限过宽，请执行 chmod 600 配置文件")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ConfigError("配置文件不存在、不可读或 JSON 格式错误") from None
    if not isinstance(data, dict) or not isinstance(data.get("accounts"), list):
        raise ConfigError("配置必须包含 accounts 数组")
    names = set()
    for row in data["accounts"]:
        if not isinstance(row, dict):
            raise ConfigError("每个账号必须是 JSON 对象")
        name = row.get("name")
        if not isinstance(name, str) or not name.strip() or len(name) > 80 or any(ord(c) < 32 for c in name):
            raise ConfigError("账号名称必须为 1–80 个可打印字符")
        if name in names:
            raise ConfigError("账号名称不能重复")
        names.add(name)
        if not isinstance(row.get("enabled", True), bool):
            raise ConfigError("enabled 必须为布尔值")
        if ("token" in row) == ("token_env" in row):
            raise ConfigError("每个账号必须且只能指定 token 或 token_env")
        if "token" in row:
            clean_token(row["token"])
        elif not isinstance(row["token_env"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", row["token_env"]):
            raise ConfigError("token_env 必须为合法环境变量名")
    return data


def write_config(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=".accounts-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


@contextmanager
def locked(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            if os.name == "nt":
                # msvcrt 从当前位置锁定一个字节；文件需先有内容。
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, PermissionError):
            raise BusyError("另一个任务正在使用此配置") from None
        yield
    finally:
        os.close(fd)


def desktop_session(args):
    # 只按显式命令读取当前用户的桌面登录态；不读取 QODER_TOKEN。
    import qoder_desktop as desktop
    overrides = {"QODER_AUTH_DIR": args.auth_dir, "QODER_EXE": args.qoder_exe}
    previous = {key: os.environ.get(key) for key in overrides}
    try:
        for key, value in overrides.items():
            if value:
                os.environ[key] = str(Path(value).expanduser().resolve())
        session = desktop.load_session()
        if desktop._token_expired(session):
            raise ConfigError("桌面登录态已过期，请重新登录 Qoder CN 后提取")
        return clean_token(session.get("token"))
    except desktop.QoderAuthError:
        # 不输出客户端、钥匙串或解密助手的原始异常数据。
        raise ConfigError("无法读取 Qoder CN 登录态：请在已登录的 Windows/macOS 客户端上以同一系统用户运行；检查数据目录、客户端路径与钥匙串授权") from None
    except (ValueError, OSError):
        raise ConfigError("桌面登录态格式错误或不可读，请重新登录客户端后重试") from None
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def export_token(path, token):
    # 不覆盖已有文件，也不跟随指向已有文件的符号链接。
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(token + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Api:
    def __init__(self, token, timeout=20, retries=3):
        self.token, self.timeout, self.retries = token, timeout, retries
        self.opener = urllib.request.build_opener(NoRedirect())

    def call(self, path, method="GET"):
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(
                BASE_URL + path, method=method,
                data=b"" if method == "POST" else None,
                headers={"Accept": "application/json", "User-Agent": "Qoder/claim",
                         "Cosy-ClientType": "10", "Authorization": "Bearer " + self.token})
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    code, raw = response.status, response.read(1048577)
            except urllib.error.HTTPError as exc:
                code, raw = exc.code, b""
                exc.close()
            except (urllib.error.URLError, OSError, TimeoutError):
                code, raw = 0, b""
            if (code == 0 or code == 429 or 500 <= code < 600) and attempt < self.retries:
                time.sleep((5, 15, 30)[attempt])
                continue
            if code == 401:
                raise ApiError("AUTH_REJECTED", "token 已失效，请重新登录客户端后更新 token")
            if code == 403:
                raise ApiError("FORBIDDEN", "服务端拒绝访问，请检查账号资格或认证要求")
            if code == 0:
                raise ApiError("NETWORK", "网络连接失败或请求超时")
            if code != 200:
                raise ApiError("ERROR", "接口请求失败，HTTP %s" % code)
            if len(raw) > 1048576:
                raise ApiError("ERROR", "接口响应过大")
            try:
                body = json.loads(raw)
            except (ValueError, UnicodeError):
                raise ApiError("ERROR", "接口返回非 JSON 数据") from None
            if not isinstance(body, dict):
                raise ApiError("ERROR", "接口响应格式不符")
            # 两种响应形式均兼容；错误信封不能被误判为无活动。
            if isinstance(body.get("data"), dict):
                body = body["data"]
            return body

    def campaigns(self):
        data = self.call("/sash/api/v1/me/campaigns")
        rows = data.get("campaigns")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ApiError("ERROR", "活动列表格式不符，接口可能已变更")
        return rows

    def claim(self, campaign_id):
        if not isinstance(campaign_id, str) or not campaign_id:
            raise ApiError("ERROR", "活动缺少 campaignId")
        return self.call("/sash/api/v1/me/campaigns/%s/claim" % urllib.parse.quote(campaign_id, safe=""), "POST")


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def amount(row):
    benefit = row.get("benefit")
    value = benefit.get("amount") if isinstance(benefit, dict) else None
    return value if number(value) and value >= 0 else None


def active(row, now):
    for key in ("startAt", "endAt"):
        if row.get(key) is not None and not number(row[key]):
            raise ApiError("ERROR", "活动时间格式不符")
    return (row.get("startAt") is None or now >= row["startAt"]) and (row.get("endAt") is None or now < row["endAt"])


def process_account(api, action, dry_run=False):
    rows = api.campaigns()
    now = time.time()
    eligible = [r for r in rows if r.get("actionType") == "CLAIM_BENEFIT" and active(r, now)]
    todo = [r for r in eligible if r.get("claimStatus") == "CLAIMABLE"]
    done = [r for r in eligible if r.get("claimStatus") == "CLAIMED"]
    if action == "status" or dry_run:
        return {"result": "DRY_RUN" if dry_run else "OK", "report": "查询完成，可领取 %s 项" % len(todo),
                "claimable": len(todo), "already_claimed": len(done)}
    if not todo:
        if done and len(done) == len(eligible):
            return {"result": "ALREADY", "report": "当前周期已领取"}
        if eligible:
            return {"result": "PENDING", "report": "活动存在，但有活动当前不可领取"}
        return {"result": "INACTIVE", "report": "当前没有可领取的活动"}
    claimed, errors = [], []
    for row in todo:
        try:
            data = api.claim(row.get("campaignId"))
            if data.get("status") != "CLAIMED":
                raise ApiError("ERROR", "领取未返回 CLAIMED，请查询状态确认")
            value = amount(data)
            claimed.append({"credits": amount(row) if value is None else value,
                            "replayed": data.get("replayed") is True})
        except ApiError as exc:
            errors.append({"result": exc.result, "report": str(exc)})
            if exc.result in ("AUTH_REJECTED", "FORBIDDEN"):
                break
    # replayed 仅代表服务端确认已领，不计入本轮新到账积分。
    values = [r["credits"] for r in claimed if not r["replayed"] and r["credits"] is not None]
    result = errors[0]["result"] if errors else "CLAIMED"
    return {"result": result, "report": "领取完成" if not errors else "部分或全部活动领取失败",
            "claimed_count": len(claimed), "credits": sum(values) if values else None,
            "replayed_count": sum(r["replayed"] for r in claimed), "errors": errors}


def emit(data, secrets=()):
    data = dict(data, time=datetime.now(CN).isoformat(timespec="seconds"))
    text = json.dumps(data, ensure_ascii=False)
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            text = text.replace(secret, "[REDACTED]")
    print(text, flush=True)


def run_accounts(args, data):
    rows = [r for r in data["accounts"] if r.get("enabled", True) and (args.account is None or r["name"] == args.account)]
    if not rows:
        raise ConfigError("没有匹配的已启用账号，请先添加账号")
    # 先收集全部 token，使前一账号输出也不会泄露后一账号的 token。
    secrets = [r["token"] for r in data["accounts"] if "token" in r]
    secrets += [os.environ.get(r["token_env"], "") for r in data["accounts"] if "token_env" in r]
    counts = Counter()
    failed = 0
    for index, row in enumerate(rows):
        try:
            token = clean_token(row.get("token", os.environ.get(row.get("token_env", ""), "")))
            secrets.append(token)
            out = process_account(Api(token, args.timeout, args.retries), args.action, args.dry_run)
        except ConfigError:
            out = {"result": "NO_TOKEN", "report": "账号 token 为空或格式错误，请更新配置或环境变量"}
        except ApiError as exc:
            out = {"result": exc.result, "report": str(exc)}
        except Exception:
            out = {"result": "ERROR", "report": "账号处理异常，请检查配置或更新脚本"}
        ok = out["result"] in SUCCESS
        counts[out["result"]] += 1
        failed += not ok
        emit(dict(out, account=row["name"], needs_attention=not ok), secrets)
        if index < len(rows) - 1:
            time.sleep(args.interval)
    emit({"result": "SUMMARY", "total": len(rows), "failed": failed, "counts": dict(counts), "needs_attention": failed > 0}, secrets)
    return 1 if failed else 0


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="账号配置文件路径")
    subs = p.add_subparsers(dest="action", required=True)
    subs.add_parser("init", help="创建空账号配置")
    subs.add_parser("list", help="列出账号，不显示 token")
    add = subs.add_parser("add", help="添加或更新账号，默认隐藏输入 token")
    add.add_argument("name")
    source = add.add_mutually_exclusive_group()
    source.add_argument("--token-env", help="引用环境变量，配置中不保存 token")
    source.add_argument("--token-stdin", action="store_true", help="从标准输入读取 token")
    for action in ("import-desktop", "extract-token"):
        sub = subs.add_parser(action, help="读取桌面 token 并保存账号" if action == "import-desktop" else "提取桌面 token 到文件")
        if action == "import-desktop":
            sub.add_argument("name", help="保存到配置的账号名称，同名则更新")
        else:
            sub.add_argument("--output", required=True, type=Path, help="token 输出文件（必须不存在）")
        sub.add_argument("--auth-dir", help="Qoder CN 数据目录（包含 auth.v1.dat）")
        sub.add_argument("--qoder-exe", help="macOS Qoder CN.app 内主可执行文件路径")
    remove = subs.add_parser("remove", help="删除账号")
    remove.add_argument("name")
    for action in ("run", "status"):
        sub = subs.add_parser(action, help="依次签到" if action == "run" else "只查状态，不领取")
        sub.add_argument("--account", help="仅处理指定账号")
        sub.add_argument("--dry-run", action="store_true", help="只查可领取项")
        sub.add_argument("--interval", type=float, default=3, help="账号间隔秒数（默认 3）")
        sub.add_argument("--timeout", type=float, default=20, help="单次请求超时秒数")
        sub.add_argument("--retries", type=int, choices=range(4), default=3, help="网络/429/5xx 重试次数（0–3）")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    path = args.config.expanduser().resolve()
    try:
        if args.action == "extract-token":
            target = args.output.expanduser().absolute()
            if target.exists() or target.is_symlink():
                raise ConfigError("输出文件已存在，请指定新文件名")
            export_token(target, desktop_session(args))
            emit({"result": "OK", "report": "token 已保存到指定文件，未输出到终端；请妥善保管"})
            return 0
        with locked(path):
            if args.action == "init":
                if path.exists():
                    read_config(path)
                    emit({"result": "OK", "report": "配置已存在，未覆盖"})
                else:
                    write_config(path, {"accounts": []})
                    emit({"result": "OK", "report": "已创建空配置，请用 add 添加账号"})
                return 0
            data = {"accounts": []} if args.action == "import-desktop" and not path.exists() else read_config(path)
            if args.action in ("run", "status"):
                if not math.isfinite(args.interval) or args.interval < 0 or not math.isfinite(args.timeout) or args.timeout <= 0:
                    raise ConfigError("interval 必须为非负有限数，timeout 必须为正有限数")
                return run_accounts(args, data)
            if args.action == "list":
                emit({"result": "OK", "accounts": [{"name": r["name"], "enabled": r.get("enabled", True),
                     "source": "env" if "token_env" in r else "file"} for r in data["accounts"]]})
                return 0
            if args.action in ("add", "import-desktop"):
                if not args.name.strip() or len(args.name) > 80 or any(ord(c) < 32 for c in args.name):
                    raise ConfigError("账号名称必须为 1–80 个可打印字符")
                row = {"name": args.name, "enabled": True}
                if args.action == "import-desktop":
                    row["token"] = desktop_session(args)
                elif args.token_env:
                    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.token_env):
                        raise ConfigError("环境变量名不合法")
                    row["token_env"] = args.token_env
                else:
                    if not args.token_stdin and not sys.stdin.isatty():
                        raise ConfigError("非交互输入请显式使用 --token-stdin")
                    row["token"] = clean_token(sys.stdin.read(32769) if args.token_stdin else getpass.getpass("Qoder CN token（隐藏输入）: "))
                for index, old in enumerate(data["accounts"]):
                    if old["name"] == args.name:
                        data["accounts"][index] = row
                        break
                else:
                    data["accounts"].append(row)
            else:
                if not any(r["name"] == args.name for r in data["accounts"]):
                    raise ConfigError("指定账号不存在")
                data["accounts"] = [r for r in data["accounts"] if r["name"] != args.name]
            write_config(path, data)
            emit({"result": "OK", "report": "账号配置已保存"})
            return 0
    except BusyError as exc:
        emit({"result": "BUSY", "report": str(exc), "needs_attention": True})
        return 3
    except ConfigError as exc:
        emit({"result": "CONFIG_ERROR", "report": str(exc), "needs_attention": True})
        return 2
    except OSError:
        emit({"result": "ERROR", "report": "文件读写失败，请检查目录权限", "needs_attention": True})
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
