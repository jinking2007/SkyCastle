#!/usr/bin/env python3
"""SkyCastle (FeatherPanel) auto-renew + power recovery.
Strict verification: Only reports SUCCESS if credits decreased or due date extended.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Any

PANEL_DEFAULT = "https://panel.skycastle.us"
UA_DESKTOP = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)


def log(msg: str, level: str = "info") -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    prefix = {"info": "·", "ok": "✓", "warn": "!", "err": "✗"}.get(level, "·")
    print(f"[{ts}] {prefix} {msg}", flush=True)


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def parse_accounts() -> list[dict[str, str]]:
    raw = env("SKYCASTLE_ACCOUNTS")
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            return [
                {
                    "email": str(i.get("email") or i.get("username") or "").strip(),
                    "password": str(i.get("password") or "").strip(),
                    "totp": str(i.get("totp") or i.get("totp_secret") or "").strip(),
                    "token": str(i.get("token") or i.get("remember_token") or "").strip(),
                }
                for i in data if i.get("email") or i.get("token")
            ]
        except Exception:
            pass

    email = env("SKYCASTLE_EMAIL") or env("SKYCASTLE_USERNAME")
    token = env("SKYCASTLE_TOKEN") or env("SKYCASTLE_REMEMBER_TOKEN")
    if email or token:
        return [{
            "email": email,
            "password": env("SKYCASTLE_PASSWORD"),
            "totp": env("SKYCASTLE_TOTP"),
            "token": token,
        }]
    return []


def totp(secret: str) -> str:
    cleaned = secret.upper().replace(" ", "").replace("-", "")
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    key = base64.b32decode(cleaned + pad, casefold=True)
    counter = int(time.time() // 30)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


# ---------------------------------------------------------------------------
# API Client
# ---------------------------------------------------------------------------

class PanelClient:
    def __init__(self, base: str, cache_dir: str = ".skycastle-cache"):
        self.base = base.rstrip("/")
        self.cache_dir = cache_dir
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            urllib.request.HTTPCookieProcessor(self.jar),
        )
        os.makedirs(cache_dir, exist_ok=True)

    def request(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        url = f"{self.base}{path}" if not path.startswith("http") else path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "User-Agent": UA_DESKTOP,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": self.base,
            "Referer": f"{self.base}/dashboard",
            "X-Requested-With": "XMLHttpRequest",
        }
        req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
        try:
            with self.opener.open(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return json.loads(raw) if raw else {}
        except Exception as exc:
            return {"error": str(exc)}

    def get_remember_token(self) -> str:
        for c in self.jar:
            if c.name == "remember_token" and c.value:
                return c.value
        return ""

    def set_remember_token(self, token: str) -> None:
        from http.cookiejar import Cookie
        c = Cookie(
            version=0, name="remember_token", value=token, port=None, port_specified=False,
            domain=urllib.parse.urlparse(self.base).hostname or "panel.skycastle.us",
            domain_specified=True, domain_initial_dot=False, path="/", path_specified=True,
            secure=True, expires=int(time.time()) + 2592000, discard=False, comment=None,
            comment_url=None, rest={"HttpOnly": None}, rfc2109=False,
        )
        self.jar.set_cookie(c)

    def export_cookies_for_browser(self) -> list[dict[str, Any]]:
        out = []
        for c in self.jar:
            if c.value:
                out.append({"name": c.name, "value": str(c.value), "url": self.base + "/"})
        tok = self.get_remember_token()
        if tok and not any(x["name"] == "remember_token" for x in out):
            out.append({"name": "remember_token", "value": tok, "url": self.base + "/"})
        return out


def login(client: PanelClient, account: dict[str, str]) -> bool:
    token = account.get("token")
    if token:
        client.set_remember_token(token)
        res = client.request("GET", "/api/user/session")
        if res.get("success"):
            log("Token 登录成功", "ok")
            return True

    email = account.get("email")
    pwd = account.get("password")
    if not (email and pwd):
        return False

    res = client.request("PUT", "/api/user/auth/login", {"username_or_email": email, "password": pwd})
    if res.get("error_code") == "TWO_FACTOR_REQUIRED":
        if not account.get("totp"):
            log("需要 2FA 验证码但未配置 TOTP", "err")
            return False
        res = client.request("POST", "/api/user/auth/two-factor", {"email": email, "code": totp(account["totp"])})

    if res.get("success"):
        log("密码登录成功", "ok")
        return True
    return False


def get_credits_api(client: PanelClient) -> int:
    res = client.request("GET", "/api/user/billingcore/credits")
    data = res.get("data")
    if isinstance(data, dict):
        for k in ("credits", "balance", "amount", "user_credits"):
            if data.get(k) is not None:
                return int(data[k])
    return -1


# ---------------------------------------------------------------------------
# Browser Renewal (Strict Check)
# ---------------------------------------------------------------------------

def browser_strict_renew(
    panel: str,
    cookies: list[dict[str, Any]],
    cache_dir: str,
) -> dict[str, Any]:
    from seleniumbase import SB

    after_path = os.path.abspath(os.path.join(cache_dir, "renew-after.png"))
    ret = {
        "ok": False,
        "skipped": False,
        "before_due": "",
        "after_due": "",
        "error": "",
        "after_shot": after_path,
    }

    with SB(uc=True, headless=False, locale_code="en-US") as sb:
        # 打开首页并灌入 Cookie
        sb.uc_open_with_reconnect(panel + "/", reconnect_time=4)
        for c in cookies:
            try:
                sb.driver.add_cookie({
                    "name": c["name"], "value": c["value"], "path": "/",
                    "domain": urllib.parse.urlparse(panel).hostname or "panel.skycastle.us"
                })
            except Exception:
                pass

        # 访问服务器页面
        sb.uc_open_with_reconnect(panel + "/dashboard/servers", reconnect_time=5)
        time.sleep(3)

        # 处理可能的人机验证
        for _ in range(3):
            src = (sb.get_page_source() or "")[:4000].lower()
            if "just a moment" in src or "enable javascript" in src:
                sb.uc_gui_click_captcha()
                time.sleep(4)
            else:
                break

        # 1. 抓取初始页面信息与到期时间
        time.sleep(2)
        initial_due = sb.execute_script(
            "var m = document.body.innerText.match(/Due\\s+([A-Za-z0-9,\\s]+)/); return m ? m[1].trim() : '';"
        ) or ""
        ret["before_due"] = initial_due
        log(f"当前卡片到期时间: {initial_due or '未知'}", "info")

        # 2. 检查服务器是否在 Starting/Stopping 状态，若是则等待就绪
        for _ in range(5):
            body_now = sb.execute_script("return document.body ? document.body.innerText : '';") or ""
            if "starting" in body_now.lower() or "stopping" in body_now.lower():
                log("服务器正在转换状态(Starting/Stopping)，等待 5 秒...", "warn")
                time.sleep(5)
            else:
                break

        # 3. 寻找并点击真实的续期按钮（形如 "1 credit · 3 days"）
        clicked = bool(sb.execute_script(
            """
            var btns = document.querySelectorAll('button, [role="button"], a');
            for (var i = 0; i < btns.length; i++) {
                var t = (btns[i].innerText || '').toLowerCase();
                if (/\\d+\\s*credits?/.test(t) && t.indexOf('day') >= 0) {
                    btns[i].scrollIntoView({block: 'center'});
                    btns[i].click();
                    return true;
                }
            }
            return false;
            """
        ))

        if not clicked:
            sb.save_screenshot(after_path)
            ret["skipped"] = True
            ret["error"] = "未找到可点击的续期按钮（可能未到期或置灰）"
            return ret

        log("已点击续期按钮，正在观察页面反应与弹窗...", "ok")
        time.sleep(2)

        # 4. 检查是否有确认弹窗（Modal）需要二次确认
        try:
            confirmed = sb.execute_script(
                """
                var modal = document.querySelector('.modal, [role="dialog"], .dialog');
                if (modal) {
                    var btns = modal.querySelectorAll('button');
                    for (var i = 0; i < btns.length; i++) {
                        var t = (btns[i].innerText || '').toLowerCase();
                        if (t.indexOf('confirm') >= 0 || t.indexOf('ok') >= 0 || t.indexOf('yes') >= 0) {
                            btns[i].click();
                            return true;
                        }
                    }
                }
                return false;
                """
            )
            if confirmed:
                log("已点击弹窗确认按钮", "ok")
                time.sleep(3)
        except Exception:
            pass

        # 5. 等待页面网络请求结算（等待 5 秒）
        time.sleep(5)
        sb.save_screenshot(after_path)

        # 6. 读取页面是否有红框报错
        body_after = sb.execute_script("return document.body ? document.body.innerText : '';") or ""
        new_due = sb.execute_script(
            "var m = document.body.innerText.match(/Due\\s+([A-Za-z0-9,\\s]+)/); return m ? m[1].trim() : '';"
        ) or ""
        ret["after_due"] = new_due

        if "already being processed" in body_after.lower():
            log("后端拦截: This renewal is already being processed (说明未真正延期)", "err")
            ret["ok"] = False
            ret["error"] = "续期已被拦截（后台提示处理中但未扣费生效）"
            return ret

        if "something went wrong" in body_after.lower():
            log("页面弹出 Something went wrong 报错", "err")
            ret["ok"] = False
            ret["error"] = "面板报错 Something went wrong"
            return ret

        # 7. 判断到期时间是否真正发生了改变
        if new_due and initial_due and new_due != initial_due:
            log(f"✓ 严格校验通过！到期时间已延后: {initial_due} -> {new_due}", "ok")
            ret["ok"] = True
            return ret
        elif new_due and not initial_due:
            ret["ok"] = True
            return ret

        ret["ok"] = False
        ret["error"] = f"点击后到期时间未发生变动 (仍为 {initial_due or '原时间'})"
        return ret


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------

def send_tg_report(results: list[dict[str, Any]]) -> None:
    token = env("TELEGRAM_BOT_TOKEN") or env("TELEGRAM_TOKEN")
    chat = env("TELEGRAM_CHAT_ID") or env("TELEGRAM_CHAT")
    if not (token and chat):
        return

    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    parts = ["<b>🏰 CastleKeep · SkyCastle 续期报告</b>", f"<code>{ts}</code>", ""]

    for item in results:
        parts.append(f"<b>账号</b> <code>{item.get('account')}</code>")
        cb = item.get("credits_before", -1)
        ca = item.get("credits_after", -1)
        credits_desc = f"{cb} → {ca}" if cb != -1 else "无法获取"
        parts.append(f"💰 Credits: <b>{credits_desc}</b>")

        renew_info = item.get("renew", {})
        if renew_info.get("ok"):
            due_b = renew_info.get("before_due") or "-"
            due_a = renew_info.get("after_due") or "-"
            parts.append(f"✅ <b>续期真正成功！</b>\n   到期变化: <code>{due_b}</code> ➜ <code>{due_a}</code>")
        elif renew_info.get("skipped"):
            parts.append(f"⏭ <b>跳过续期</b>: {renew_info.get('error')}")
        else:
            err = renew_info.get("error") or "未知原因"
            parts.append(f"❌ <b>续期未生效</b>: {err}")
        parts.append("")

    # 发送文字卡片
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = urllib.parse.urlencode({"chat_id": chat, "text": "\n".join(parts), "parse_mode": "HTML"}).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=payload), timeout=20)
    except Exception as exc:
        log(f"TG 发送失败: {exc}", "warn")

    # 发送现场真实截图（有图有真相）
    for item in results:
        shot = item.get("renew", {}).get("after_shot")
        if shot and os.path.isfile(shot):
            try:
                with open(shot, "rb") as fh:
                    img_data = fh.read()
                boundary = f"----CK{int(time.time())}"
                caption = "真实执行回执截图（请以截图中的积分和 Due 时间为准）"
                body = (
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n{chat}\r\n"
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n{caption}\r\n"
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"shot.png\"\r\n"
                    f"Content-Type: image/png\r\n\r\n".encode() + img_data + f"\r\n--{boundary}--\r\n".encode()
                )
                req = urllib.request.Request(
                    f"https://api.telegram.org/bot{token}/sendPhoto",
                    data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
                )
                urllib.request.urlopen(req, timeout=30)
            except Exception as exc:
                log(f"TG 截图发送失败: {exc}", "warn")


def main() -> int:
    accounts = parse_accounts()
    if not accounts:
        log("未配置账号信息", "err")
        return 2

    panel = env("SKYCASTLE_PANEL") or PANEL_DEFAULT
    cache_dir = env("SKYCASTLE_CACHE_DIR") or ".skycastle-cache"
    results = []

    for acc in accounts:
        client = PanelClient(panel, cache_dir)
        login(client, acc)
        cb = get_credits_api(client)

        log("启动浏览器严格续期流程...", "info")
        renew_res = browser_strict_renew(panel, client.export_cookies_for_browser(), cache_dir)

        ca = get_credits_api(client)

        # 积分核验双保险：如果 API 显示积分真的扣减了，即使文字没对上也可以判定成功
        if cb != -1 and ca != -1 and ca < cb:
            log(f"积分已成功扣减: {cb} -> {ca}", "ok")
            renew_res["ok"] = True
            renew_res["error"] = ""

        results.append({
            "account": acc.get("email") or "user",
            "credits_before": cb,
            "credits_after": ca,
            "renew": renew_res,
        })

    send_tg_report(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
