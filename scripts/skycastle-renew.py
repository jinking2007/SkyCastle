#!/usr/bin/env python3
"""SkyCastle server renewal via the panel's first-party API key.

Uses the panel's official API key auth (Authorization: Bearer <key>), the same
mechanism the "API Keys" page in your account provides. No browsers, no cookie
scraping, no captcha solving, no bot-detection evasion.

Auth (pick one):
    SKYCASTLE_API_KEY     API key from Account -> API Keys      (preferred)
    SKYCASTLE_TOKEN       remember_token cookie value           (legacy)
    SKYCASTLE_EMAIL + SKYCASTLE_PASSWORD [+ SKYCASTLE_TOTP]     (last resort)

Modes:
    --discover   list every API route whose path mentions renew/extend/expiry
                 (reads /api/openapi.json). Run this first.
    --check      report per-server due dates, change nothing
    (default)    renew servers whose remaining time is under --before-hours

Endpoint:
    Renewal path is resolved in this order:
      1. SKYCASTLE_RENEW_PATH
      2. auto-discovered from /api/openapi.json
      3. POST /api/user/servers/{id}/renew

Exit codes:  0 ok,  1 renewal problem,  2 config/auth problem
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
from datetime import datetime, timezone
from http.cookiejar import Cookie, CookieJar
from typing import Any

PANEL_DEFAULT = "https://panel.skycastle.us"
UA = "skycastle-renew/1.0 (personal automation; +https://panel.skycastle.us)"
DEFAULT_RENEW_BEFORE_HOURS = 36.0

DUE_KEYS = ("renewal_due_at", "due_at", "expires_at", "next_renewal_at",
            "renewal_date", "due", "renews_at", "expiry", "expiry_date")
COST_KEYS = ("renewal_cost", "renew_cost", "renewal_credits", "renew_credits",
             "price_credits", "cost_credits", "credits")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def log(msg: str, level: str = "info") -> None:
    mark = {"info": "·", "ok": "✓", "warn": "!", "err": "✗"}.get(level, "·")
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {mark} {msg}", flush=True)


class ApiError(RuntimeError):
    def __init__(self, message: str, code: str = "", status: int = 0, payload: Any = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.payload = payload or {}


class ConfigError(RuntimeError):
    pass


def totp(secret: str) -> str:
    cleaned = secret.upper().replace(" ", "").replace("-", "")
    cleaned += "=" * ((8 - len(cleaned) % 8) % 8)
    key = base64.b32decode(cleaned, casefold=True)
    counter = int(time.time() // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def looks_like_html(raw: str) -> bool:
    head = (raw or "")[:600].lower()
    return ("<!doctype html" in head or "<html" in head) and "{" not in head[:200]


# --------------------------------------------------------------------------- #
class Panel:
    def __init__(self, base: str, api_key: str = "", timeout: int = 30):
        self.base = base.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.jar = CookieJar()
        self.user: dict[str, Any] = {}
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            urllib.request.HTTPCookieProcessor(self.jar),
        )

    def set_remember_token(self, token: str) -> None:
        host = urllib.parse.urlparse(self.base).hostname or "panel.skycastle.us"
        self.jar.set_cookie(Cookie(
            version=0, name="remember_token", value=token.strip(),
            port=None, port_specified=False, domain=host, domain_specified=True,
            domain_initial_dot=False, path="/", path_specified=True, secure=True,
            expires=int(time.time()) + 60 * 60 * 24 * 30, discard=False,
            comment=None, comment_url=None, rest={"HttpOnly": None}, rfc2109=False,
        ))

    def request(self, method: str, path: str, body: Any = None,
                retries: int = 3) -> dict[str, Any]:
        url = path if path.startswith("http") else f"{self.base}{path}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": self.base,
            "Referer": f"{self.base}/dashboard",
            "X-Requested-With": "XMLHttpRequest",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        last: Exception | None = None
        for attempt in range(1, retries + 1):
            req = urllib.request.Request(url, data=data, method=method.upper(),
                                         headers=headers)
            try:
                with self.opener.open(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8", "replace")
                    if not raw.strip():
                        return {"success": True, "data": None, "status": resp.status}
                    try:
                        payload = json.loads(raw)
                    except json.JSONDecodeError:
                        if looks_like_html(raw):
                            raise ApiError(
                                "panel returned HTML instead of JSON "
                                "(this IP is being blocked by the panel's firewall)",
                                "BLOCKED", resp.status)
                        return {"success": False, "message": raw[:200], "status": resp.status}
                    if isinstance(payload, dict):
                        payload.setdefault("status", resp.status)
                    return payload
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", "replace")
                try:
                    payload = json.loads(raw) if raw.strip() else {}
                except json.JSONDecodeError:
                    payload = {"message": ("<html challenge page>" if looks_like_html(raw)
                                           else raw.strip().replace("\n", " ")[:160])}
                code = str(payload.get("error_code") or payload.get("code") or "")
                msg = str(payload.get("message") or exc.reason or f"HTTP {exc.code}")
                err = ApiError(msg[:200], code, exc.code, payload)
                if exc.code in (429, 502, 503, 504) and attempt < retries:
                    wait = min(60, 8 * attempt)
                    log(f"{method} {path} -> {exc.code}, retry in {wait}s", "warn")
                    time.sleep(wait)
                    last = err
                    continue
                raise err
            except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
                last = exc
                if attempt < retries:
                    wait = min(20, 4 * attempt)
                    log(f"{method} {path} network error: {exc}; retry in {wait}s", "warn")
                    time.sleep(wait)
                    continue
                raise ApiError(f"network failure: {exc}", "NETWORK") from exc
        raise ApiError(f"request failed: {last}", "NETWORK")


# --------------------------------------------------------------------------- #
# auth
# --------------------------------------------------------------------------- #
def authenticate(client: Panel) -> None:
    if client.api_key:
        who = "api key"
        try:
            servers = list_servers(client)
            log(f"API key accepted · account reachable ({len(servers)} server(s))", "ok")
        except ApiError as exc:
            raise ConfigError(
                f"API key rejected: {exc} [{exc.code}]. Check that the key is active, "
                f"not IP-locked to another address, and has account permissions."
            ) from exc
        # Best-effort: identify the user (some setups gate this endpoint).
        for probe in ("/api/user/session", "/api/user/api-clients/validate"):
            try:
                payload = client.request("GET", probe, retries=1)
                data = payload.get("data") if isinstance(payload, dict) else None
                if isinstance(data, dict):
                    client.user = data.get("user") if isinstance(data.get("user"), dict) else data
                    break
            except ApiError:
                continue
        name = client.user.get("username") or client.user.get("email") or who
        log(f"authenticated as {name}", "ok")
        return

    token = env("SKYCASTLE_TOKEN")
    if token:
        client.set_remember_token(token)
        payload = client.request("GET", "/api/user/session")
        data = payload.get("data") or payload
        client.user = data.get("user") if isinstance(data, dict) and isinstance(data.get("user"), dict) else (data if isinstance(data, dict) else {})
        log(f"session ok via SKYCASTLE_TOKEN · {client.user.get('username') or 'user'}", "ok")
        return

    email = env("SKYCASTLE_EMAIL") or env("SKYCASTLE_USERNAME")
    password = env("SKYCASTLE_PASSWORD")
    if not email or not password:
        raise ConfigError(
            "Set SKYCASTLE_API_KEY (Account -> API Keys). This is the supported way "
            "to automate the panel. SKYCASTLE_TOKEN or email+password also work."
        )

    payload = client.request("PUT", "/api/user/auth/login",
                             {"username_or_email": email, "password": password}, retries=1)
    code = str(payload.get("error_code") or "")
    if "CAPTCHA" in code:
        raise ConfigError(
            "Password login needs a Turnstile token. Create an API key in "
            "Account -> API Keys and use SKYCASTLE_API_KEY instead."
        )
    if code == "TWO_FACTOR_REQUIRED" or (not payload.get("success") and "2FA" in str(payload.get("message", "")).upper()):
        secret = env("SKYCASTLE_TOTP")
        if not secret:
            raise ConfigError("2FA enabled — set SKYCASTLE_TOTP, or use SKYCASTLE_API_KEY.")
        payload = client.request("POST", "/api/user/auth/two-factor",
                                 {"email": email, "code": totp(secret)}, retries=1)
    if not payload.get("success"):
        raise ApiError(str(payload.get("message") or "login failed"),
                       str(payload.get("error_code") or ""), 401, payload)
    user = (payload.get("data") or {}).get("user") or {}
    client.user = user if isinstance(user, dict) else {}
    log(f"login ok · {client.user.get('username') or email}", "ok")


# --------------------------------------------------------------------------- #
# openapi discovery
# --------------------------------------------------------------------------- #
RENEW_HINTS = ("renew", "extend", "expiry", "expiration")


def discover(client: Panel) -> list[dict[str, str]]:
    """Read /api/openapi.json and list routes whose path hints at renewal."""
    try:
        spec = client.request("GET", "/api/openapi.json", retries=1)
    except ApiError as exc:
        log(f"openapi.json unavailable: {exc}", "warn")
        return []
    paths = spec.get("paths") if isinstance(spec, dict) else None
    if not isinstance(paths, dict):
        log("openapi.json has no usable 'paths' section", "warn")
        return []
    found: list[dict[str, str]] = []
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        low = str(path).lower()
        if not any(h in low for h in RENEW_HINTS):
            continue
        for method in ("post", "put", "patch", "get", "delete"):
            if method in ops and isinstance(ops[method], dict):
                found.append({
                    "method": method.upper(),
                    "path": str(path),
                    "summary": str(ops[method].get("summary") or ""),
                })
    return found


def resolve_renew_endpoint(client: Panel, discovered: list[dict[str, str]],
                           ident: str) -> tuple[str, str]:
    """Return (METHOD, url_path) for the renewal call."""
    custom = env("SKYCASTLE_RENEW_PATH")
    if custom:
        return ("POST", custom.replace("{id}", ident).replace("{uuid}", ident)
                .replace("{uuidShort}", ident))
    # prefer an authed user-scope server route
    ranked = sorted(discovered, key=lambda e: (
        "/api/user/" not in e["path"],
        "server" not in e["path"].lower(),
    ))
    for entry in ranked:
        if "/api/user/" in entry["path"] or "/api/user" == entry["path"][:9]:
            path = (entry["path"].replace("{uuidShort}", ident)
                    .replace("{uuid}", ident).replace("{id}", ident))
            return (entry["method"], path)
    return ("POST", f"/api/user/servers/{ident}/renew")


# --------------------------------------------------------------------------- #
# servers / due dates
# --------------------------------------------------------------------------- #
def list_servers(client: Panel) -> list[dict[str, Any]]:
    payload = client.request("GET", "/api/user/servers")
    data = payload.get("data")
    if isinstance(data, dict):
        for key in ("data", "servers"):
            if isinstance(data.get(key), list):
                return data[key]
    if isinstance(data, list):
        return data
    return []


def get_credits(client: Panel) -> int | None:
    try:
        payload = client.request("GET", "/api/user/billingcore/credits", retries=1)
    except ApiError:
        return None
    data = payload.get("data")
    if isinstance(data, dict):
        for key in ("credits", "balance", "amount", "user_credits"):
            if data.get(key) is not None:
                return int(data[key])
    if isinstance(data, (int, float)):
        return int(data)
    return None


def server_id(srv: dict[str, Any]) -> str:
    for key in ("uuidShort", "uuid_short", "identifier", "uuid", "id"):
        if srv.get(key):
            return str(srv[key])
    return ""


def server_name(srv: dict[str, Any]) -> str:
    return str(srv.get("name") or server_id(srv) or "?")


def _walk(obj: Any, depth: int = 0):
    if depth > 3 or not isinstance(obj, dict):
        return
    yield obj
    for key in ("renewal", "billing", "expiry", "attributes"):
        if isinstance(obj.get(key), dict):
            yield from _walk(obj[key], depth + 1)


def server_renewal(srv: dict[str, Any]) -> dict[str, Any]:
    due = cost = None
    for obj in _walk(srv):
        for key in DUE_KEYS:
            if due is None and obj.get(key) is not None:
                due = obj[key]
        for key in COST_KEYS:
            if cost is None and obj.get(key) is not None:
                cost = obj[key]
    return {"due": due, "cost": cost}


def parse_time(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        v = float(text)
        return v / 1000.0 if v > 1e11 else v
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y %H:%M", "%Y/%m/%d %H:%M"):
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def fmt_time(epoch: float | None) -> str:
    return "unknown" if epoch is None else datetime.fromtimestamp(
        epoch, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# --------------------------------------------------------------------------- #
def renew(client: Panel, ident: str, discovered: list[dict[str, str]]) -> dict[str, Any]:
    method, path = resolve_renew_endpoint(client, discovered, ident)
    try:
        payload = client.request(method, path, {}, retries=1)
    except ApiError as exc:
        if exc.status in (404, 405, 501) or exc.code in {
            "NOT_FOUND", "METHOD_NOT_ALLOWED", "ROUTE_NOT_FOUND",
        }:
            return {"ok": False, "path": path, "method": method, "code": "NO_ENDPOINT",
                    "error": (f"no renewal endpoint at {method} {path}. "
                              f"Run --discover to list real routes, then set "
                              f"SKYCASTLE_RENEW_PATH.")}
        return {"ok": False, "path": path, "method": method,
                "code": exc.code or "HTTP", "error": str(exc)[:200]}
    if not payload.get("success", True):
        return {"ok": False, "path": path, "method": method,
                "code": str(payload.get("error_code") or ""),
                "error": str(payload.get("message") or "renew rejected")[:200]}
    return {"ok": True, "path": path, "method": method, "data": payload.get("data")}


def check_and_renew(client: Panel, apply: bool, before_hours: float,
                    discovered: list[dict[str, str]]) -> dict[str, Any]:
    report: dict[str, Any] = {"servers": [], "actions": []}
    credits = get_credits(client)
    if credits is not None:
        report["credits_before"] = credits
        log(f"credits balance = {credits}", "info")

    servers = list_servers(client)
    if not servers:
        log("no servers returned", "warn")
        return report

    now = time.time()
    for srv in servers:
        ident = server_id(srv)
        name = server_name(srv)
        info = server_renewal(srv)
        due_epoch = parse_time(info.get("due"))
        left_h = None if due_epoch is None else (due_epoch - now) / 3600.0
        row = {"name": name, "id": ident, "due_at": fmt_time(due_epoch),
               "hours_left": None if left_h is None else round(left_h, 1),
               "cost": info.get("cost"), "renewed": False, "reason": ""}
        log(f"server {name} · {ident} · due={row['due_at']} · "
            f"left={row['hours_left']}h · cost={row['cost']}")

        if not ident:
            row["reason"] = "no usable server id"
        elif due_epoch is None:
            row["reason"] = "no due date exposed by the API"
        elif left_h is not None and left_h > before_hours:
            row["reason"] = f"{left_h:.1f}h left (threshold {before_hours:g}h)"
        elif not apply:
            row["reason"] = f"due in {left_h:.1f}h — check mode"
        else:
            result = renew(client, ident, discovered)
            if result.get("ok"):
                row["renewed"] = True
                row["reason"] = f"renewed via {result['method']} {result['path']}"
                report["actions"].append(f"renew {name} ok")
                log(f"renewed {name} via {result['method']} {result['path']}", "ok")
                time.sleep(2)
            else:
                row["reason"] = result.get("error") or "renew failed"
                report["actions"].append(f"renew {name} failed: {row['reason']}")
                log(f"renew failed for {name}: {row['reason']}", "err")
        report["servers"].append(row)

    if apply and report["actions"]:
        after = get_credits(client)
        if after is not None:
            report["credits_after"] = after
            log(f"credits after = {after}", "info")
        try:
            refreshed = {server_id(s): s for s in list_servers(client)}
            for row in report["servers"]:
                s2 = refreshed.get(row["id"])
                if s2:
                    row["due_after_at"] = fmt_time(parse_time(server_renewal(s2).get("due")))
        except ApiError as exc:
            log(f"post-renew refresh failed: {exc}", "warn")
    return report


# --------------------------------------------------------------------------- #
def notify(text: str) -> None:
    token = env("TELEGRAM_BOT_TOKEN") or env("TELEGRAM_TOKEN")
    chat = env("TELEGRAM_CHAT_ID") or env("TELEGRAM_CHAT")
    if token and chat:
        try:
            body = urllib.parse.urlencode({
                "chat_id": chat, "text": text[:3900],
                "disable_web_page_preview": "true",
            }).encode()
            urllib.request.urlopen(urllib.request.Request(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data=body, method="POST"), timeout=20).read()
            log("telegram notification sent", "ok")
        except Exception as exc:  # noqa: BLE001
            log(f"telegram notify failed: {exc}", "warn")


def format_report(report: dict[str, Any], panel: str, mode: str) -> str:
    lines = ["SkyCastle renewal",
             time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
             f"panel: {panel}   mode: {mode}"]
    if report.get("credits_before") is not None:
        c = f"credits: {report['credits_before']}"
        if report.get("credits_after") is not None:
            c += f" -> {report['credits_after']}"
        lines.append(c)
    lines.append("")
    for row in report.get("servers", []):
        if row.get("renewed"):
            lines.append(f"RENEWED  {row['name']}  was due {row['due_at']}"
                         f" -> {row.get('due_after_at', '?')}")
        else:
            lines.append(f"skipped  {row['name']}  due {row['due_at']}  ({row['reason']})")
    if not report.get("servers"):
        lines.append("(no servers)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SkyCastle renewal via panel API key")
    parser.add_argument("--panel", default=env("SKYCASTLE_PANEL") or PANEL_DEFAULT)
    parser.add_argument("--check", action="store_true",
                        help="report due dates without renewing")
    parser.add_argument("--discover", action="store_true",
                        help="list API routes related to renewal and exit")
    parser.add_argument("--before-hours", type=float,
                        default=float(env("SKYCASTLE_RENEW_BEFORE_HOURS")
                                      or DEFAULT_RENEW_BEFORE_HOURS))
    parser.add_argument("--timeout", type=int, default=int(env("SKYCASTLE_TIMEOUT") or "30"))
    args = parser.parse_args(argv)

    client = Panel(args.panel, api_key=env("SKYCASTLE_API_KEY"), timeout=args.timeout)
    try:
        authenticate(client)
    except ConfigError as exc:
        log(str(exc), "err")
        return 2
    except ApiError as exc:
        log(f"auth failed: {exc} [{exc.code}]", "err")
        return 2

    discovered = discover(client)

    if args.discover:
        if not discovered:
            log("no renewal-ish routes found in /api/openapi.json", "warn")
            print("\nNothing matched. Routes containing "
                  f"{', '.join(RENEW_HINTS)} were not found.\n")
            return 0
        print("\nRoutes mentioning renewal / extension:\n")
        for e in discovered:
            print(f"  {e['method']:<6} {e['path']}   {e['summary']}")
        print("\nSet SKYCASTLE_RENEW_PATH to the one for servers if it is not "
              "auto-detected.\n")
        return 0

    apply = not args.check and env("SKYCASTLE_DRY_RUN", "").lower() not in {"1", "true", "yes"}
    report = check_and_renew(client, apply=apply, before_hours=args.before_hours,
                             discovered=discovered)
    text = format_report(report, args.panel, "apply" if apply else "check")
    print("\n" + text, flush=True)
    notify(text)

    if not apply:
        return 0
    return 1 if any("failed" in a for a in report.get("actions", [])) else 0


if __name__ == "__main__":
    sys.exit(main())
