#!/usr/bin/env python3
"""SkyCastle (FeatherPanel) auto-renew + server power recovery.

Designed to run on GitHub Actions or cron.
Supports API & browser-based renewal (SeleniumBase UC).

Renewal flow:
  1. Login via remember_token / Password (+ 2FA TOTP / Turnstile)
  2. Open /dashboard/servers and click server card RENEWAL button (costs credits)
  3. Auto-start / restart offline servers (power recovery)
  4. Capture post-renewal screenshots and push report to Telegram/Discord
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


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def log(msg: str, level: str = "info") -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    prefix = {"info": "·", "ok": "✓", "warn": "!", "err": "✗"}.get(level, "·")
    print(f"[{ts}] {prefix} {msg}", flush=True)


def _looks_like_waf_html(raw: str) -> bool:
    """Detect CrowdSec / Cloudflare / generic HTML challenge pages."""
    s = (raw or "")[:4000].lower()
    if not s:
        return False
    markers = (
        "crowdsec",
        "captcha",
        "cf-browser-verification",
        "attention required",
        "access denied",
        "you have been blocked",
        "sorry, you have been blocked",
    )
    if any(m in s for m in markers):
        return True
    if ("<!doctype html" in s or "<html" in s) and "{" not in s[:200]:
        return True
    return False


def totp(secret: str, for_time: float | None = None) -> str:
    cleaned = secret.upper().replace(" ", "").replace("-", "")
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    key = base64.b32decode(cleaned + pad, casefold=True)
    counter = int((for_time if for_time is not None else time.time()) // 30)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def parse_accounts() -> list[dict[str, str]]:
    raw = env("SKYCASTLE_ACCOUNTS")
    if raw:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        out = []
        for item in data:
            out.append(
                {
                    "email": str(item.get("email") or item.get("username") or "").strip(),
                    "password": str(item.get("password") or "").strip(),
                    "totp": str(item.get("totp") or item.get("totp_secret") or "").strip(),
                    "token": str(item.get("token") or item.get("remember_token") or "").strip(),
                    "plan_id": str(item.get("plan_id") or "").strip(),
                }
            )
        return [a for a in out if a["email"] or a["token"]]

    email = env("SKYCASTLE_EMAIL") or env("SKYCASTLE_USERNAME")
    password = env("SKYCASTLE_PASSWORD")
    totp_secret = env("SKYCASTLE_TOTP")
    token = env("SKYCASTLE_TOKEN") or env("SKYCASTLE_REMEMBER_TOKEN")
    plan_id = env("SKYCASTLE_PLAN_ID")
    if not email and not token:
        return []
    return [
        {
            "email": email,
            "password": password,
            "totp": totp_secret,
            "token": token,
            "plan_id": plan_id,
        }
    ]


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class ApiError(RuntimeError):
    def __init__(self, message: str, code: str = "", status: int = 0, payload: Any = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.payload = payload or {}


class PanelClient:
    def __init__(self, base: str, cache_dir: str = ".skycastle-cache"):
        self.base = base.rstrip("/")
        self.cache_dir = cache_dir
        self.jar = CookieJar()
        ctx = ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
        )
        self.last_user: dict[str, Any] = {}
        os.makedirs(cache_dir, exist_ok=True)

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "User-Agent": UA_DESKTOP,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": self.base,
            "Referer": f"{self.base}/dashboard",
            "X-Requested-With": "XMLHttpRequest",
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
        }
        if extra:
            headers.update(extra)
        return headers

    def set_remember_token(self, token: str) -> None:
        token = token.strip()
        if not token:
            return
        from http.cookiejar import Cookie

        cookie = Cookie(
            version=0,
            name="remember_token",
            value=token,
            port=None,
            port_specified=False,
            domain=urllib.parse.urlparse(self.base).hostname or "panel.skycastle.us",
            domain_specified=True,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=True,
            expires=int(time.time()) + 60 * 60 * 24 * 30,
            discard=False,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": None},
            rfc2109=False,
        )
        self.jar.set_cookie(cookie)

    def import_browser_cookies(self, cookies: list[dict[str, Any]]) -> int:
        from http.cookiejar import Cookie

        host = urllib.parse.urlparse(self.base).hostname or "panel.skycastle.us"
        n = 0
        for c in cookies or []:
            name = c.get("name")
            value = c.get("value")
            if not name or value is None:
                continue
            domain = (c.get("domain") or host).lstrip(".")
            path = c.get("path") or "/"
            try:
                cookie = Cookie(
                    version=0,
                    name=str(name),
                    value=str(value),
                    port=None,
                    port_specified=False,
                    domain=domain,
                    domain_specified=True,
                    domain_initial_dot=domain.startswith("."),
                    path=path,
                    path_specified=True,
                    secure=bool(c.get("secure", True)),
                    expires=int(time.time()) + 60 * 60 * 24 * 30,
                    discard=False,
                    comment=None,
                    comment_url=None,
                    rest={"HttpOnly": None},
                    rfc2109=False,
                )
                self.jar.set_cookie(cookie)
                n += 1
            except Exception:
                continue
        if n:
            log(f"imported {n} browser cookies into API client", "ok")
        return n

    def get_remember_token(self) -> str:
        for c in self.jar:
            if c.name == "remember_token" and c.value:
                return c.value
        return ""

    def export_cookies_for_browser(self) -> list[dict[str, Any]]:
        base = self.base.rstrip("/")
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for c in self.jar:
            if not c.value or c.name in seen:
                continue
            seen.add(c.name)
            out.append({"name": c.name, "value": str(c.value), "url": base + "/"})
        token = self.get_remember_token()
        if token and "remember_token" not in seen:
            out.append({"name": "remember_token", "value": token, "url": base + "/"})
        return out

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        timeout: int = 45,
        retries: int = 4,
    ) -> dict[str, Any]:
        url = path if path.startswith("http") else f"{self.base}{path}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        last_err: Exception | None = None
        for attempt in range(1, retries + 1):
            req = urllib.request.Request(url, data=data, method=method.upper(), headers=self._headers())
            try:
                with self.opener.open(req, timeout=timeout) as resp:
                    raw = resp.read().decode("utf-8", "replace")
                    if not raw:
                        return {"success": True, "data": None, "status": resp.status}
                    try:
                        payload = json.loads(raw)
                    except json.JSONDecodeError:
                        if _looks_like_waf_html(raw):
                            raise ApiError(
                                "WAF/CrowdSec blocked this IP (HTML ban page).",
                                "WAF_BLOCKED",
                                resp.status,
                            )
                        return {"success": True, "data": raw[:200], "status": resp.status, "raw": True}
                    if isinstance(payload, dict):
                        payload.setdefault("status", resp.status)
                    return payload
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", "replace")
                if _looks_like_waf_html(raw):
                    msg = f"WAF/CrowdSec ban (HTTP {exc.code})."
                    log(f"{method} {path} → {msg}", "err")
                    raise ApiError(msg, "WAF_BLOCKED", exc.code) from exc
                try:
                    payload = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    snippet = raw.strip().replace("\n", " ")[:120]
                    payload = {"message": snippet or f"HTTP {exc.code}"}
                code = str(payload.get("error_code") or payload.get("code") or "")
                msg = str(
                    payload.get("message")
                    or payload.get("error_message")
                    or exc.reason
                    or f"HTTP {exc.code}"
                )
                if len(msg) > 180:
                    msg = msg[:177] + "..."
                if exc.code in (429, 502, 503, 504) and attempt < retries:
                    wait = min(45, 6 * attempt)
                    log(f"{method} {path} → {exc.code}, retry in {wait}s ({code or msg})", "warn")
                    time.sleep(wait)
                    last_err = ApiError(msg, code, exc.code, payload)
                    continue
                raise ApiError(msg, code, exc.code, payload) from exc
            except ApiError:
                raise
            except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
                last_err = exc
                wait = min(20, 3 * attempt)
                log(f"{method} {path} network error: {exc}; retry in {wait}s", "warn")
                time.sleep(wait)
        raise ApiError(f"request failed after retries: {last_err}", "NETWORK", 0)

    def save_cache(self, key: str) -> None:
        token = self.get_remember_token()
        path = os.path.join(self.cache_dir, f"{key}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"remember_token": token, "saved_at": int(time.time())}, fh)

    def load_cache(self, key: str) -> str:
        path = os.path.join(self.cache_dir, f"{key}.json")
        if not os.path.isfile(path):
            return ""
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            return str(data.get("remember_token") or "")
        except (OSError, json.JSONDecodeError):
            return ""


# ---------------------------------------------------------------------------
# captcha (optional Capsolver)
# ---------------------------------------------------------------------------

def solve_turnstile(site_key: str, page_url: str, api_key: str) -> str:
    def call(path: str, payload: dict[str, Any]) -> dict[str, Any]:
        raw = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"https://api.capsolver.com/{path}",
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())

    created = call(
        "createTask",
        {
            "clientKey": api_key,
            "task": {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": page_url,
                "websiteKey": site_key,
            },
        },
    )
    if created.get("errorId"):
        raise ApiError(created.get("errorDescription") or "capsolver create failed", "CAPTCHA")
    task_id = created.get("taskId")
    for _ in range(24):
        time.sleep(3)
        polled = call("getTaskResult", {"clientKey": api_key, "taskId": task_id})
        if polled.get("status") == "ready":
            sol = polled.get("solution") or {}
            token = sol.get("token") or sol.get("gRecaptchaResponse") or ""
            if token:
                return token
        if polled.get("errorId"):
            raise ApiError(polled.get("errorDescription") or "capsolver error", "CAPTCHA")
    raise ApiError("capsolver timed out", "CAPTCHA")


def public_turnstile_key(client: PanelClient) -> str:
    key = env("SKYCASTLE_TURNSTILE_SITEKEY")
    if key:
        return key
    for path in ("/api/settings", "/api/system/settings"):
        try:
            payload = client.request("GET", path, retries=1)
            data = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(data, dict):
                for k in ("turnstile_key_pub", "TURNSTILE_KEY_PUB", "site_key"):
                    if data.get(k):
                        return str(data[k])
        except ApiError:
            continue
    return ""


# ---------------------------------------------------------------------------
# auth / session
# ---------------------------------------------------------------------------

def login(client: PanelClient, account: dict[str, str]) -> dict[str, Any]:
    cache_key = (account.get("email") or "token").replace("@", "_at_")
    token = account.get("token") or client.load_cache(cache_key)
    if token:
        client.set_remember_token(token)
        try:
            session = get_session(client)
            log(f"cookie login ok · {session.get('username') or session.get('email') or 'user'}", "ok")
            client.last_user = session
            client.save_cache(cache_key)
            return session
        except ApiError as exc:
            log(f"cached token rejected ({exc.code or exc}); falling back to password", "warn")

    email = account.get("email") or ""
    password = account.get("password") or ""
    if not email or not password:
        raise ApiError(
            "Need SKYCASTLE_EMAIL + SKYCASTLE_PASSWORD, or SKYCASTLE_TOKEN",
            "NO_CREDENTIALS",
        )
    if len(password) < 8:
        raise ApiError("Password must be at least 8 characters", "INVALID_DATA_LENGTH")

    body: dict[str, Any] = {"username_or_email": email, "password": password}

    capsolver = env("CAPSOLVER_KEY")
    if capsolver:
        site_key = public_turnstile_key(client)
        if site_key:
            try:
                body["turnstile_token"] = solve_turnstile(site_key, f"{client.base}/auth/login", capsolver)
                log("Turnstile solved via Capsolver", "ok")
            except ApiError as exc:
                log(f"captcha solve skipped: {exc}", "warn")

    try:
        payload = client.request("PUT", "/api/user/auth/login", body)
    except ApiError as exc:
        if exc.code == "CAPTCHA_TOKEN_REQUIRED" and capsolver:
            site_key = public_turnstile_key(client) or env("SKYCASTLE_TURNSTILE_SITEKEY")
            if not site_key:
                raise ApiError("Panel requires Turnstile key", "CAPTCHA_TOKEN_REQUIRED", 400) from exc
            body["turnstile_token"] = solve_turnstile(site_key, f"{client.base}/auth/login", capsolver)
            payload = client.request("PUT", "/api/user/auth/login", body)
        elif exc.code == "TWO_FACTOR_REQUIRED":
            payload = {"error_code": "TWO_FACTOR_REQUIRED", "data": exc.payload.get("data") or {"email": email}}
        else:
            raise

    code = str(payload.get("error_code") or "")
    if code == "TWO_FACTOR_REQUIRED" or (not payload.get("success") and "2FA" in str(payload.get("message", "")).upper()):
        if not account.get("totp"):
            raise ApiError("2FA required — set SKYCASTLE_TOTP (base32 secret)", "TWO_FACTOR_REQUIRED", 401)
        two_email = email if "@" in email else str((payload.get("data") or {}).get("email") or email)
        payload = client.request(
            "POST",
            "/api/user/auth/two-factor",
            {"email": two_email, "code": totp(account["totp"])},
        )

    if not payload.get("success"):
        raise ApiError(str(payload.get("message") or "login failed"), str(payload.get("error_code") or ""), 401, payload)

    data = payload.get("data") or {}
    user = data.get("user") if isinstance(data, dict) else {}
    if not isinstance(user, dict):
        user = {}
    token = client.get_remember_token()
    if not token and isinstance(user.get("remember_token"), str):
        client.set_remember_token(user["remember_token"])
        token = user["remember_token"]
    client.save_cache(cache_key)
    client.last_user = user
    log(f"password login ok · {user.get('username') or user.get('email') or email}", "ok")
    return user


def get_session(client: PanelClient) -> dict[str, Any]:
    payload = client.request("GET", "/api/user/session")
    if not payload.get("success"):
        raise ApiError(str(payload.get("message") or "session invalid"), str(payload.get("error_code") or ""), 400, payload)
    data = payload.get("data") or payload
    if isinstance(data, dict) and isinstance(data.get("user"), dict):
        return data["user"]
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# renewal logic
# ---------------------------------------------------------------------------

def get_credits(client: PanelClient) -> int:
    try:
        payload = client.request("GET", "/api/user/billingcore/credits")
        data = payload.get("data") if payload.get("success") else None
        if isinstance(data, dict):
            for k in ("credits", "balance", "amount", "user_credits"):
                if data.get(k) is not None:
                    return int(data[k])
        if isinstance(data, (int, float)):
            return int(data)
    except ApiError as exc:
        log(f"credits endpoint: {exc}", "warn")
    return -1


def list_subscriptions(client: PanelClient) -> tuple[list[dict[str, Any]], int]:
    payload = client.request("GET", "/api/user/billingplans/subscriptions")
    data = payload.get("data") or {}
    subs = data.get("data") if isinstance(data, dict) else data
    if not isinstance(subs, list):
        subs = []
    credits = int(data.get("user_credits") or 0) if isinstance(data, dict) else 0
    return subs, credits


def list_servers(client: PanelClient) -> list[dict[str, Any]]:
    for path in ("/api/user/servers", "/api/client/servers"):
        try:
            payload = client.request("GET", path)
            data = payload.get("data") or payload
            if isinstance(data, dict):
                if isinstance(data.get("data"), list):
                    return data["data"]
                if isinstance(data.get("servers"), list):
                    return data["servers"]
            if isinstance(data, list):
                return data
        except ApiError as exc:
            log(f"{path}: {exc}", "warn")
    return []


def server_ident(srv: dict[str, Any]) -> str:
    return str(
        srv.get("uuidShort")
        or srv.get("uuid_short")
        or srv.get("identifier")
        or srv.get("uuid")
        or srv.get("id")
        or ""
    )


def server_name(srv: dict[str, Any]) -> str:
    return str(srv.get("name") or server_ident(srv) or "?")


def server_state(srv: dict[str, Any]) -> str:
    return str(
        srv.get("status")
        or (srv.get("state") if not isinstance(srv.get("state"), dict) else "")
        or ((srv.get("attributes") or {}).get("status") if isinstance(srv.get("attributes"), dict) else "")
        or ""
    ).lower()


def server_renewal_info(srv: dict[str, Any]) -> dict[str, Any]:
    candidates = [
        srv,
        srv.get("renewal") if isinstance(srv.get("renewal"), dict) else None,
        srv.get("billing") if isinstance(srv.get("billing"), dict) else None,
        srv.get("attributes") if isinstance(srv.get("attributes"), dict) else None,
    ]
    due = None
    cost = None
    period = None
    for obj in candidates:
        if not isinstance(obj, dict):
            continue
        for k in ("renewal_due_at", "due_at", "expires_at", "next_renewal_at", "renewal_date", "due"):
            if obj.get(k) is not None and due is None:
                due = obj.get(k)
        for k in ("renewal_cost", "renew_cost", "renewal_credits", "price_credits", "credits"):
            if obj.get(k) is not None and cost is None:
                cost = obj.get(k)
        for k in ("renewal_period", "period", "billing_period"):
            if obj.get(k) is not None and period is None:
                period = obj.get(k)
    return {"due": due, "cost": cost, "period": period}


def power_server(client: PanelClient, ident: str, action: str) -> bool:
    action = action.lower().strip()
    paths_bodies = [
        (f"/api/user/servers/{ident}/power/{action}", None),
        (f"/api/user/servers/{ident}/power", {"signal": action}),
    ]
    for path, body in paths_bodies:
        try:
            client.request("POST", path, body, retries=2)
            log(f"power {action} → {ident}", "ok")
            return True
        except ApiError as exc:
            if exc.code == "WAF_BLOCKED":
                return False
            log(f"power {action} {ident} via {path}: {str(exc)[:120]}", "warn")
    return False


def start_server(client: PanelClient, ident: str) -> bool:
    return power_server(client, ident, "start")


def stop_server(client: PanelClient, ident: str) -> bool:
    return power_server(client, ident, "stop")


def restart_server(client: PanelClient, ident: str) -> bool:
    if power_server(client, ident, "restart"):
        return True
    log(f"restart fallback: stop→start for {ident}", "warn")
    ok_stop = stop_server(client, ident)
    time.sleep(3)
    ok_start = start_server(client, ident)
    return ok_stop and ok_start


def _is_missing_route(exc: ApiError) -> bool:
    msg = str(exc).lower()
    return (
        exc.status in (404, 405, 501)
        or exc.code in {"NOT_FOUND", "METHOD_NOT_ALLOWED", "ROUTE_NOT_FOUND"}
        or "route does not exist" in msg
        or "not found" in msg
    )


def renew_server(client: PanelClient, ident: str, extra_ids: list[str] | None = None) -> dict[str, Any]:
    ids = [ident]
    for x in extra_ids or []:
        if x and x not in ids:
            ids.append(x)

    custom = env("SKYCASTLE_RENEW_PATH")
    paths_bodies = []
    if custom:
        for i in ids:
            p = custom.replace("{id}", i).replace("{uuid}", i).replace("{uuidShort}", i)
            paths_bodies.append((p, {}))
    else:
        i = ids[0]
        paths_bodies = [
            (f"/api/user/servers/{i}/renew", {}),
            (f"/api/client/servers/{i}/renew", {}),
            (f"/api/user/servers/{i}/renewal", {}),
        ]
        if len(ids) > 1:
            paths_bodies.append((f"/api/user/servers/{ids[1]}/renew", {}))

    last_err: Exception | None = None
    for path, body in paths_bodies:
        try:
            payload = client.request("POST", path, body, retries=1)
            log(f"server renew → {ident} via {path}", "ok")
            data = payload.get("data") if isinstance(payload, dict) else payload
            return {"ok": True, "path": path, "data": data if isinstance(data, dict) else payload}
        except ApiError as exc:
            last_err = exc
            if exc.code == "WAF_BLOCKED":
                return {"ok": False, "path": path, "error": str(exc), "code": "WAF_BLOCKED"}
            if _is_missing_route(exc):
                time.sleep(1.5)
                continue
            log(f"renew {ident} via {path}: {exc} [{exc.code}]", "warn")
            if exc.status in (400, 402, 403, 409, 422) or "credit" in str(exc).lower():
                return {"ok": False, "path": path, "error": str(exc)[:180], "code": exc.code}
            time.sleep(1.5)

    err = str(last_err) if last_err else "no renew endpoint matched"
    return {"ok": False, "path": None, "error": err[:177], "code": getattr(last_err, "code", "")}


def run_renew(client: PanelClient, account: dict[str, str]) -> dict[str, Any]:
    credits_before = get_credits(client)
    log(f"credits balance = {credits_before}", "info")
    report: dict[str, Any] = {
        "credits_before": credits_before,
        "credits": credits_before,
        "credits_after": credits_before,
        "subscriptions": [],
        "servers": [],
        "renewals": [],
        "restarts": [],
        "actions": [],
    }

    try:
        subs, sub_credits = list_subscriptions(client)
        if sub_credits:
            report["credits"] = sub_credits
            credits_before = sub_credits
            report["credits_before"] = credits_before
        for sub in subs:
            name = sub.get("plan_name") or sub.get("name") or f"plan#{sub.get('plan_id')}"
            status = sub.get("status")
            nxt = sub.get("next_renewal_at") or sub.get("expires_at")
            cost = sub.get("total_credits") or sub.get("price_credits") or sub.get("credits")
            report["subscriptions"].append({
                "name": name,
                "status": status,
                "next_renewal_at": nxt,
                "cost": cost,
                "id": sub.get("id"),
            })
            log(f"sub {name} · status={status} · next={nxt} · cost={cost}", "info")
    except ApiError as exc:
        log(f"subscriptions: {exc} ({exc.code})", "warn")

    do_renew = env("SKYCASTLE_SERVER_RENEW", "1") not in {"0", "false", "no"}
    do_power_fix = env("SKYCASTLE_START_SERVERS", "1") not in {"0", "false", "no"}
    need_power_states = {"offline", "stopped", "stopping", "exited", "suspended", "dead"}

    servers = list_servers(client)
    if not servers:
        log("no servers returned (account may be empty)", "info")

    for srv in servers:
        ident = server_ident(srv)
        name = server_name(srv)
        state = server_state(srv)
        ren_info = server_renewal_info(srv)
        full_uuid = str(srv.get("uuid") or srv.get("uuidFull") or srv.get("server_uuid") or "")
        extra_ids = [full_uuid] if full_uuid and full_uuid != ident else []
        row: dict[str, Any] = {
            "name": name,
            "id": ident,
            "state_before": state,
            "state_after": state,
            "renewal_due_before": ren_info.get("due"),
            "renewal_due_after": ren_info.get("due"),
            "renewal_cost": ren_info.get("cost"),
            "renewed": False,
            "restarted": False,
            "started": False,
            "errors": [],
        }
        log(f"server {name} · {ident} · state={state or 'unknown'} · due={ren_info.get('due')} · cost={ren_info.get('cost')}", "info")

        # 1) 优先浏览器点击续期
        if do_renew and ident:
            if not row.get("renewal_due_before") and srv.get("expires_at"):
                row["renewal_due_before"] = srv.get("expires_at")
            cookies = client.export_cookies_for_browser()
            result = browser_click_renew(
                panel=client.base,
                cookies=cookies,
                cache_dir=client.cache_dir,
                server_name=name,
                account=account,
            )
            if not result.get("ok") and not result.get("skipped") and env("SKYCASTLE_RENEW_PATH"):
                api_result = renew_server(client, ident, extra_ids=extra_ids)
                if api_result.get("ok"):
                    result = api_result

            if result.get("ok") and result.get("skipped"):
                report["actions"].append(f"renew {name} skipped (not clickable)")
                report["renewals"].append({
                    "name": name,
                    "id": ident,
                    "ok": True,
                    "skipped": True,
                    "path": result.get("path"),
                    "error": result.get("error"),
                    "due_before": row["renewal_due_before"],
                    "cost": row["renewal_cost"],
                    "after": result.get("after"),
                })
                log(f"· 续期跳过 {name}: {result.get('error')}", "info")
            elif result.get("ok"):
                row["renewed"] = True
                report["actions"].append(f"renew {name} ok via {result.get('path')}")
                log(f"✓ 续期完成 {name} via {result.get('path')}", "ok")
                if result.get("due_after") or result.get("next_renewal"):
                    row["renewal_due_after"] = result.get("due_after") or result.get("next_renewal")
                report["renewals"].append({
                    "name": name,
                    "id": ident,
                    "ok": True,
                    "skipped": False,
                    "path": result.get("path"),
                    "due_before": row["renewal_due_before"],
                    "due_after": row["renewal_due_after"],
                    "next_renewal": row["renewal_due_after"],
                    "cost": row["renewal_cost"],
                    "after": result.get("after"),
                })
            else:
                err = result.get("error") or "renew failed"
                row["errors"].append(f"renew: {err}")
                report["actions"].append(f"renew {name} failed: {err}")
                report["renewals"].append({
                    "name": name,
                    "id": ident,
                    "ok": False,
                    "error": err,
                    "due_before": row["renewal_due_before"],
                    "cost": row["renewal_cost"],
                    "after": result.get("after"),
                })
                log(f"✗ 续期失败 {name}: {err}", "err")

        # 2) 异常服务器开机或重启保活
        if do_power_fix and ident and state in need_power_states:
            log(f"server {name} state={state} → need power recovery", "warn")
            if state == "stopping":
                time.sleep(5)
            ok = start_server(client, ident)
            if not ok:
                ok = restart_server(client, ident)
                row["restarted"] = ok
                report["restarts"].append({"name": name, "id": ident, "ok": ok, "reason": state})
            else:
                row["started"] = True
                report["restarts"].append({"name": name, "id": ident, "ok": True, "action": "start", "reason": state})
            time.sleep(2)

        report["servers"].append(row)

    try:
        credits_after = get_credits(client)
        report["credits_after"] = credits_after
        report["credits"] = credits_after
        log(f"credits after = {credits_after} (was {credits_before})", "info")
    except Exception as exc:
        log(f"credits refresh: {exc}", "warn")

    return report


# ---------------------------------------------------------------------------
# browser (SeleniumBase UC)
# ---------------------------------------------------------------------------

def _is_login_url(url: str) -> bool:
    u = (url or "").lower()
    return "login" in u or "/auth/" in u


def _sb_challenge_visible(sb: Any) -> bool:
    try:
        src = (sb.get_page_source() or "")[:8000].lower()
        if 'type="password"' in src or "sign in" in src or "username or email" in src:
            return (
                "checking if the site connection is secure" in src
                or "just a moment" in src
                or "enable javascript and cookies to continue" in src
            )
        return (
            "checking if the site connection is secure" in src
            or "just a moment" in src
            or "enable javascript and cookies to continue" in src
            or ("verify you are human" in src and "password" not in src)
        )
    except Exception:
        return False


def _sb_click_turnstile_once(sb: Any) -> None:
    try:
        sb.uc_gui_click_captcha()
        log("uc_gui_click_captcha (turnstile widget)", "ok")
        time.sleep(4)
    except Exception as exc:
        log(f"uc_gui_click_captcha: {exc}", "warn")


def _sb_handle_cloudflare(sb: Any, max_retry: int = 3) -> bool:
    if not _sb_challenge_visible(sb):
        return True
    log("Cloudflare interstitial — uc_gui_click_captcha…", "warn")
    for i in range(max_retry):
        try:
            sb.uc_gui_click_captcha()
            time.sleep(5)
            if not _sb_challenge_visible(sb):
                log("interstitial passed", "ok")
                return True
        except Exception as exc:
            log(f"uc_gui_click_captcha: {exc}", "warn")
        time.sleep(2)
    return False


def _sb_wait_challenge_gone(sb: Any, timeout: int = 15) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if not _sb_challenge_visible(sb):
            return True
        _sb_handle_cloudflare(sb, max_retry=1)
        time.sleep(1)
    return not _sb_challenge_visible(sb)


def _sb_fill_field(sb: Any, selectors: list[str], value: str, label: str) -> bool:
    if not value:
        return False
    for sel in selectors:
        try:
            if not sb.is_element_visible(sel):
                continue
            sb.wait_for_element_visible(sel, timeout=5)
            try:
                sb.click(sel)
                sb.clear(sel)
                sb.type(sel, value)
            except Exception:
                sb.execute_script(
                    "arguments[0].value = arguments[1];"
                    "arguments[0].dispatchEvent(new Event('input',{bubbles:true}));"
                    "arguments[0].dispatchEvent(new Event('change',{bubbles:true}));",
                    sb.find_element(sel),
                    value,
                )
            time.sleep(0.3)
            return True
        except Exception:
            continue
    return False


def _sb_click_login(sb: Any) -> bool:
    for sel in (
        'button:contains("Sign in")',
        'button:contains("Sign In")',
        'button:contains("Login")',
        'button:contains("登录")',
        'button[type="submit"]',
    ):
        try:
            if sb.is_element_visible(sel):
                try:
                    sb.uc_click(sel)
                except Exception:
                    sb.click(sel)
                log(f"clicked login {sel}", "ok")
                return True
        except Exception:
            continue
    return False


def _sb_browser_login(sb: Any, panel: str, email: str, password: str) -> bool:
    login_url = panel.rstrip("/") + "/auth/login"
    log(f"browser open login {login_url}", "info")
    try:
        sb.uc_open_with_reconnect(login_url, reconnect_time=6)
    except Exception:
        sb.open(login_url)
    time.sleep(3)
    _sb_handle_cloudflare(sb)
    time.sleep(1)

    email_sels = ['input[type="email"]', 'input[name="email"]', 'input[name="username_or_email"]', 'input[type="text"]']
    pass_sels = ['input[type="password"]', 'input[name="password"]']

    if not _sb_fill_field(sb, email_sels, email, "email") or not _sb_fill_field(sb, pass_sels, password, "password"):
        return False

    _sb_click_turnstile_once(sb)
    time.sleep(2)

    for attempt in range(4):
        _sb_fill_field(sb, email_sels, email, "email")
        _sb_fill_field(sb, pass_sels, password, "password")
        _sb_click_login(sb)
        time.sleep(4)
        if _sb_challenge_visible(sb):
            _sb_handle_cloudflare(sb, max_retry=2)
            time.sleep(2)
        for _ in range(10):
            url = (sb.get_current_url() or "").lower()
            if not _is_login_url(url):
                log(f"browser login ok → {sb.get_current_url()}", "ok")
                return True
            time.sleep(1)
        if attempt < 3:
            _sb_click_turnstile_once(sb)
            time.sleep(2)
    return False


def _sb_open_servers(
    sb: Any,
    panel: str,
    cookies: list[dict[str, Any]] | None,
    account: dict[str, str] | None,
) -> bool:
    panel = panel.rstrip("/")
    target = panel + "/dashboard/servers"
    account = account or {}

    try:
        sb.uc_open_with_reconnect(panel + "/", reconnect_time=4)
    except Exception:
        sb.open(panel + "/")
    time.sleep(1)
    _sb_handle_cloudflare(sb, max_retry=2)

    if cookies:
        for c in cookies:
            name = c.get("name")
            value = c.get("value")
            if not name or not value:
                continue
            try:
                sb.driver.add_cookie({
                    "name": name,
                    "value": str(value),
                    "path": "/",
                    "domain": urllib.parse.urlparse(panel).hostname or "panel.skycastle.us",
                })
            except Exception:
                pass

    try:
        sb.uc_open_with_reconnect(target, reconnect_time=5)
    except Exception:
        sb.open(target)
    time.sleep(3)
    _sb_handle_cloudflare(sb)
    _sb_wait_challenge_gone(sb, timeout=12)

    if _is_login_url(sb.get_current_url() or ""):
        email = account.get("email") or env("SKYCASTLE_EMAIL") or ""
        password = account.get("password") or env("SKYCASTLE_PASSWORD") or ""
        if not email or not password:
            return False
        if not _sb_browser_login(sb, panel, email, password):
            return False
        try:
            sb.uc_open_with_reconnect(target, reconnect_time=5)
        except Exception:
            sb.open(target)
        time.sleep(3)
        _sb_handle_cloudflare(sb)
        _sb_wait_challenge_gone(sb, timeout=12)

    return not _is_login_url(sb.get_current_url() or "")


def _sb_save_shot(sb: Any, path: str) -> str | None:
    try:
        _sb_wait_challenge_gone(sb, timeout=10)
        time.sleep(0.8)
        sb.save_screenshot(path)
        if os.path.isfile(path) and os.path.getsize(path) > 1000:
            log(f"screenshot → {path} ({os.path.getsize(path)} bytes)", "ok")
            return path
    except Exception as exc:
        log(f"screenshot failed: {exc}", "warn")
    return None


def browser_click_renew(
    panel: str,
    cookies: list[dict[str, Any]],
    cache_dir: str = ".skycastle-cache",
    server_name: str = "",
    account: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        from seleniumbase import SB
    except ImportError:
        return {"ok": False, "error": "seleniumbase not installed", "code": "NO_SB"}

    os.makedirs(cache_dir, exist_ok=True)
    before = os.path.abspath(os.path.join(cache_dir, "renew-before.png"))
    after = os.path.abspath(os.path.join(cache_dir, "renew-after.png"))

    try:
        with SB(uc=True, headless=False, locale_code="zh-CN") as sb:
            if not _sb_open_servers(sb, panel, cookies, account or {}):
                _sb_save_shot(sb, before)
                return {
                    "ok": False,
                    "error": f"browser on login page ({sb.get_current_url()})",
                    "code": "AUTH_FAILED",
                    "before": before if os.path.isfile(before) else None,
                }

            try:
                for label in ("Unassigned", "By Folder", "All Servers"):
                    try:
                        if sb.is_element_visible(f'span:contains("{label}")'):
                            sb.click(f'span:contains("{label}")')
                    except Exception:
                        pass
                for _ in range(4):
                    sb.execute_script("window.scrollBy(0, 400);")
                    time.sleep(0.6)
                sb.execute_script("window.scrollTo(0, 0);")
                time.sleep(1)
            except Exception as exc:
                log(f"prepare servers UI: {exc}", "warn")

            _sb_save_shot(sb, before)

            info = {}
            try:
                info = sb.execute_script(
                    """
                    var body = document.body ? document.body.innerText : '';
                    var hasRenewal = body.indexOf('RENEWAL') >= 0 || body.indexOf('续期') >= 0;
                    var buttons = [];
                    var clickable = null;
                    var disabledFound = false;

                    function isDisabled(el) {
                        if (!el) return true;
                        if (el.disabled || (el.getAttribute('aria-disabled') || '') === 'true') return true;
                        var cls = (el.className ? String(el.className) : '').toLowerCase();
                        if (cls.indexOf('cursor-not-allowed') >= 0 || cls.indexOf('pointer-events-none') >= 0) return true;
                        try {
                            var st = window.getComputedStyle(el);
                            if (st && (st.pointerEvents === 'none' || parseFloat(st.opacity) < 0.5)) return true;
                        } catch (e) {}
                        return false;
                    }

                    function isRenewAction(text) {
                        var low = (text || '').toLowerCase().replace(/\\s+/g, ' ').trim();
                        if (!low || low.length > 50) return false;
                        if (/\\d+\\s*credits?/.test(low) || low.indexOf('续期') >= 0) return true;
                        if (low.indexOf('renew') >= 0 && low.indexOf('renewal') < 0) return true;
                        return false;
                    }

                    var nodes = document.querySelectorAll('button, a, [role="button"]');
                    for (var i = 0; i < nodes.length; i++) {
                        var b = nodes[i];
                        var text = (b.innerText || b.textContent || '').replace(/\\s+/g, ' ').trim();
                        if (!isRenewAction(text)) continue;
                        var vis = b.offsetParent !== null;
                        var dis = isDisabled(b);
                        buttons.push({text: text, disabled: dis, visible: vis});
                        if (!vis) continue;
                        if (dis) { disabledFound = true; continue; }
                        if (!clickable) clickable = b;
                    }

                    if (clickable) {
                        try { clickable.scrollIntoView({block:'center'}); } catch (e) {}
                        clickable.setAttribute('data-skycastlereew', '1');
                    }
                    return {
                        hasRenewal: hasRenewal,
                        disabledFound: disabledFound,
                        canClick: !!clickable,
                        buttons: buttons.slice(0, 15)
                    };
                    """
                )
            except Exception as exc:
                log(f"renew DOM scan: {exc}", "warn")
                info = {}

            if not info.get("hasRenewal") and not info.get("canClick"):
                _sb_save_shot(sb, after)
                return {
                    "ok": True,
                    "skipped": True,
                    "path": "browser:RENEWAL-skip",
                    "error": "RENEWAL section not found",
                    "code": "NO_RENEWAL_UI",
                    "after": after if os.path.isfile(after) else None,
                }

            if not info.get("canClick"):
                _sb_save_shot(sb, after)
                return {
                    "ok": True,
                    "skipped": True,
                    "path": "browser:RENEWAL-skip",
                    "error": "RENEWAL button not clickable / time not reached",
                    "code": "SKIP_NOT_CLICKABLE",
                    "after": after if os.path.isfile(after) else None,
                }

            clicked = bool(sb.execute_script(
                "var el = document.querySelector('[data-skycastlereew=\"1\"]'); if (!el) return false; el.click(); return true;"
            ))

            if not clicked:
                for name in ("credits", "Credits", "续期"):
                    sel = f'button:contains("{name}")'
                    try:
                        if sb.is_element_visible(sel) and sb.is_element_enabled(sel):
                            sb.click(sel)
                            clicked = True
                            break
                    except Exception:
                        continue

            if not clicked:
                _sb_save_shot(sb, after)
                return {
                    "ok": False,
                    "error": "RENEWAL action click failed",
                    "code": "CLICK_FAILED",
                    "after": after if os.path.isfile(after) else None,
                }

            time.sleep(2)
            if _sb_challenge_visible(sb):
                _sb_handle_cloudflare(sb, max_retry=3)

            for name in ("Confirm", "OK", "确认", "续期", "Renew"):
                sel = f'button:contains("{name}")'
                try:
                    if sb.is_element_visible(sel) and sb.is_element_enabled(sel):
                        sb.click(sel)
                        time.sleep(2)
                        break
                except Exception:
                    continue

            time.sleep(3)
            _sb_wait_challenge_gone(sb, timeout=10)
            next_renewal = ""
            try:
                next_renewal = sb.execute_script(
                    """
                    var body = document.body ? document.body.innerText : '';
                    var m = body.match(/Due\\s*([\\d月日年月日\\-/]+|\\w+\\s+\\d{1,2})/i);
                    if (m) return m[1].trim();
                    m = body.match(/到期[:：]?\\s*([^\\n]+)/);
                    if (m) return m[1].trim().slice(0, 40);
                    return '';
                    """
                ) or ""
            except Exception:
                pass

            _sb_save_shot(sb, after)
            return {
                "ok": True,
                "skipped": False,
                "path": "browser:RENEWAL",
                "after": after if os.path.isfile(after) else None,
                "next_renewal": next_renewal or None,
                "due_after": next_renewal or None,
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200], "code": "BROWSER_ERROR"}


# ---------------------------------------------------------------------------
# notify
# ---------------------------------------------------------------------------

def _html_escape(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_report(results: list[dict[str, Any]]) -> str:
    lines = ["CastleKeep · SkyCastle 续期报告", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()), ""]
    for item in results:
        lines.append(f"账号 {item.get('account')}")
        renew = item.get("renew") or {}
        if renew:
            cb = renew.get("credits_before", renew.get("credits"))
            ca = renew.get("credits_after", renew.get("credits"))
            lines.append(f"  Credits: {cb} → {ca}")
            for r in renew.get("renewals") or []:
                if r.get("ok") and r.get("skipped"):
                    lines.append(f"  ⏭ 续期 {r.get('name')}: 跳过（不可点击）")
                elif r.get("ok"):
                    nxt = r.get("next_renewal") or r.get("due_after") or ""
                    extra = f" · 预计下次续期 {nxt}" if nxt else ""
                    lines.append(f"  ✅ 续期 {r.get('name')}: due {r.get('due_before')} → {r.get('due_after')} (cost={r.get('cost')}){extra}")
                else:
                    lines.append(f"  ❌ 续期 {r.get('name')}: {r.get('error')}")
            for r in renew.get("restarts") or []:
                mark = "✅" if r.get("ok") else "❌"
                lines.append(f"  {mark} 保活拉起 {r.get('name')}")
            for srv in renew.get("servers") or []:
                lines.append(f"  服务器 {srv.get('name')} {srv.get('state_before')}→{srv.get('state_after')}")
        if item.get("error"):
            lines.append(f"  ERROR: {item['error']}")
        lines.append("")
    return "\n".join(lines)


def format_report_html(results: list[dict[str, Any]]) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    parts = ["<b>🏰 CastleKeep · SkyCastle 续期报告</b>", f"<code>{_html_escape(ts)}</code>", ""]
    for item in results:
        acc = _html_escape(str(item.get("account") or "?"))
        parts.append(f"<b>账号</b> <code>{acc}</code>")
        if item.get("error"):
            err = str(item["error"])[:200]
            parts.append(f"❌ <b>ERROR</b> {_html_escape(err)}\n")
            continue
        renew = item.get("renew") or {}
        if renew:
            cb = renew.get("credits_before", renew.get("credits"))
            ca = renew.get("credits_after", renew.get("credits"))
            parts.append(f"💰 Credits: <b>{cb}</b> → <b>{ca}</b>")
            for r in renew.get("renewals") or []:
                name = _html_escape(str(r.get("name") or "?"))
                if r.get("ok") and r.get("skipped"):
                    parts.append(f"⏭ <b>{name}</b> 续期跳过（未到期或不可点）")
                elif r.get("ok"):
                    due_a = r.get("due_after") or r.get("next_renewal") or "-"
                    parts.append(f"✅ <b>{name}</b> 续期成功 · 到期: <code>{_html_escape(str(due_a))}</code>")
                else:
                    parts.append(f"❌ <b>{name}</b> 续期失败: {_html_escape(str(r.get('error') or 'unknown'))}")
            for r in renew.get("restarts") or []:
                name = _html_escape(str(r.get("name") or "?"))
                mark = "✅" if r.get("ok") else "❌"
                parts.append(f"{mark} <b>{name}</b> 状态恢复拉起")
        parts.append("")
    parts.append("<i>服务器续期 + 保活完成</i>")
    return "\n".join(parts)


def _tg_api(token: str, method: str, fields: dict[str, Any], files: dict[str, tuple[str, bytes]] | None = None) -> None:
    url = f"https://api.telegram.org/bot{token}/{method}"
    if not files:
        body = urllib.parse.urlencode({k: v for k, v in fields.items() if v is not None}).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        urllib.request.urlopen(req, timeout=30).read()
        return
    boundary = f"----CastleKeep{int(time.time())}"
    chunks = []
    for k, v in fields.items():
        if v is not None:
            chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    for name, (filename, content) in files.items():
        chunks.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
            + content + b"\r\n"
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    req = urllib.request.Request(url, data=b"".join(chunks), method="POST", headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    urllib.request.urlopen(req, timeout=45).read()


def notify(text: str, results: list[dict[str, Any]] | None = None) -> None:
    token = env("TELEGRAM_BOT_TOKEN") or env("TELEGRAM_TOKEN")
    chat = env("TELEGRAM_CHAT_ID") or env("TELEGRAM_CHAT")
    results = results or []

    if token and chat:
        html = format_report_html(results) if results else _html_escape(text)
        try:
            _tg_api(token, "sendMessage", {"chat_id": chat, "text": html[:3900], "parse_mode": "HTML", "disable_web_page_preview": "true"})
            log("telegram HTML status sent", "ok")
        except Exception as exc:
            log(f"telegram notify failed: {exc}", "warn")

        if env("SKYCASTLE_TG_SCREENSHOT", "1") not in {"0", "false", "no"}:
            for item in results:
                for r in (item.get("renew") or {}).get("renewals") or []:
                    p = r.get("after")
                    if r.get("ok") and not r.get("skipped") and p and os.path.isfile(p):
                        try:
                            with open(p, "rb") as fh:
                                data = fh.read()
                            _tg_api(token, "sendPhoto", {"chat_id": chat, "caption": f"✅ 续期凭据 · {r.get('name') or ''}"}, files={"photo": (os.path.basename(p), data)})
                            log("telegram renew-success screenshot sent", "ok")
                        except Exception as exc:
                            log(f"tg send screenshot: {exc}", "warn")

    hook = env("DISCORD_WEBHOOK")
    if hook:
        raw = json.dumps({"content": text[:1900]}).encode()
        req = urllib.request.Request(hook, data=raw, method="POST", headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=20).read()
        except Exception as exc:
            log(f"discord notify failed: {exc}", "warn")


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------

def run_account(account: dict[str, str], panel: str, cache_dir: str) -> dict[str, Any]:
    who = account.get("email") or "token-account"
    log(f"===== {who} · renew · panel={panel} =====")
    client = PanelClient(panel, cache_dir=cache_dir)
    api_ok = False
    try:
        login(client, account)
        api_ok = True
    except ApiError as exc:
        log(f"API login failed ({exc}) — falling back to browser", "warn")

    summary: dict[str, Any] = {
        "account": who,
        "panel": panel,
        "remember_token": client.get_remember_token() or account.get("token") or "",
        "api_ok": api_ok,
    }

    if api_ok:
        summary["renew"] = run_renew(client, account)
    else:
        log("browser-only renew path", "warn")
        result = browser_click_renew(panel=panel, cookies=[], cache_dir=cache_dir, server_name="", account=account)
        summary["renew"] = {
            "credits_before": None,
            "credits_after": None,
            "credits": None,
            "renewals": [{
                "name": "browser",
                "ok": bool(result.get("ok")),
                "skipped": bool(result.get("skipped")),
                "path": result.get("path"),
                "error": result.get("error"),
                "after": result.get("after"),
                "next_renewal": result.get("next_renewal"),
                "due_after": result.get("due_after"),
            }],
            "restarts": [],
            "servers": [],
            "actions": [f"browser renew: {result.get('path') or result.get('error')}"],
        }

    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SkyCastle auto-renew + server keepalive")
    parser.add_argument("command", nargs="?", default="renew", choices=["renew", "login", "run"])
    parser.add_argument("--panel", default=env("SKYCASTLE_PANEL") or PANEL_DEFAULT)
    parser.add_argument("--cache", default=env("SKYCASTLE_CACHE_DIR") or ".skycastle-cache")
    args = parser.parse_args(argv)

    accounts = parse_accounts()
    if not accounts:
        log("Missing credentials. Set SKYCASTLE_EMAIL + SKYCASTLE_PASSWORD or SKYCASTLE_TOKEN.", "err")
        return 2

    results: list[dict[str, Any]] = []
    failed = 0
    for account in accounts:
        try:
            if args.command == "login":
                client = PanelClient(args.panel, cache_dir=args.cache)
                login(client, account)
                results.append({"account": account.get("email") or "token", "status": "login ok"})
            else:
                results.append(run_account(account, args.panel, args.cache))
        except Exception as exc:
            failed += 1
            log(f"{account.get('email')}: {exc}", "err")
            results.append({"account": account.get("email"), "error": str(exc)})

    report = format_report(results)
    print("\n" + report, flush=True)
    notify(report, results=results)

    out = os.path.join(args.cache, "last-report.json")
    os.makedirs(args.cache, exist_ok=True)
    safe_results = [dict(r, cookies=None, remember_token=None) for r in results]
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(safe_results, fh, ensure_ascii=False, indent=2)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
