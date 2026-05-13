"""
Kiro manual-login module — drives an interactive browser session and captures the resulting token.
Supported providers: Google, GitHub, AWS Builder ID, IAM Identity Center.
"""
import asyncio
import base64
import hashlib
import json
import os
import secrets
import socket
import stat
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse


# Constants (shared with main.py)
REG_OIDC = "https://oidc.us-east-1.amazonaws.com"
REG_SCOPES = [
    "codewhisperer:completions", "codewhisperer:analysis",
    "codewhisperer:conversations", "codewhisperer:transformations",
    "codewhisperer:taskassist",
]
REG_REDIRECT_URI = "http://127.0.0.1:3128"
KIRO_SIGNIN_URL = "https://app.kiro.dev/signin"
ISSUER_URL = "https://view.awsapps.com/start/"
REG_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _sha1_hash(value: str) -> str:
    return hashlib.sha1(value.encode()).hexdigest()


def clear_old_session(log=print):
    """Wipe any stale AWS SSO login data from the local cache."""
    cache_dir = Path.home() / ".aws" / "sso" / "cache"
    if not cache_dir.exists():
        return
    for f in cache_dir.iterdir():
        if f.name.startswith("kiro-") or f.suffix == ".json":
            try:
                f.unlink()
                log(f"  deleted: {f.name}", "dbg")
            except Exception:
                pass
    log("Stale login data cleared", "ok")


def persist_tokens(client_id, client_secret, access_token, refresh_token, expires_in, log=print):
    """Write tokens to disk so Kiro picks them up as if the user logged in locally."""
    cache_dir = Path.home() / ".aws" / "sso" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    client_id_hash = _sha1_hash(client_id)
    expires_at_str = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    token_data = {
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": expires_at_str,
        "clientIdHash": client_id_hash,
        "authMethod": "IdC",
        "provider": "BuilderId",
        "region": "us-east-1",
    }
    token_path = cache_dir / "kiro-auth-token.json"
    token_path.write_text(json.dumps(token_data, indent=2), encoding="utf-8")
    try:
        os.chmod(token_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    log("Token written to local cache", "ok")

    client_data = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "expiresAt": (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }
    client_path = cache_dir / f"{client_id_hash}.json"
    client_path.write_text(json.dumps(client_data, indent=2), encoding="utf-8")
    try:
        os.chmod(client_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    log("Client credentials saved", "ok")


async def manual_login(method, headless=False, auto_login=True, clear_session=True,
                       log=print, cancel_check=None):
    """
    Launch a browser, let the user complete the login interactively, and capture the OAuth token.

    Args:
        method: login method ("google", "github", "builderid", "iam")
        headless: whether to run headless (usually False for manual login)
        auto_login: whether to write the token into the local AWS SSO cache
        clear_session: whether to delete existing login data first
        log: log callback - log(msg, level)
        cancel_check: optional callback returning True to abort
    Returns:
        dict with account info, or None on failure/cancel.
    """
    from curl_cffi import requests as curl_requests
    from playwright.async_api import async_playwright
    from playwright_stealth import Stealth

    if cancel_check and cancel_check():
        return None

    if clear_session:
        log("Clearing stale login data...", "info")
        clear_old_session(log)

    s = curl_requests.Session(impersonate="chrome131")

    # Phase 1: OIDC client registration
    log("Phase 1: OIDC client registration", "info")
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    state_val = secrets.token_urlsafe(32)

    reg_resp = s.post(f"{REG_OIDC}/client/register", json={
        "clientName": "Kiro IDE", "clientType": "public",
        "grantTypes": ["authorization_code", "refresh_token"],
        "issuerUrl": ISSUER_URL,
        "redirectUris": [REG_REDIRECT_URI], "scopes": REG_SCOPES,
    }, timeout=25, verify=False)
    reg = reg_resp.json()
    if "clientId" not in reg:
        log(f"OIDC register failed: {reg}", "err")
        return None
    client_id = reg["clientId"]
    client_secret = reg["clientSecret"]
    log("OIDC client registered", "ok")

    signin_url = f"{KIRO_SIGNIN_URL}?" + urlencode({
        "state": state_val,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REG_REDIRECT_URI,
        "redirect_from": "KiroIDE",
    })

    # Phase 2: local callback server + browser
    log(f"Phase 2: launching browser (headless={headless})", "info")
    authorization_code = ""

    class CallbackHandler(BaseHTTPRequestHandler):
        signin_callback_params = {}

        def do_GET(self_h):
            nonlocal authorization_code
            parsed = urlparse(self_h.path)
            qs = parse_qs(parsed.query)
            code = qs.get("code", [""])[0]
            if code:
                authorization_code = code
                log("Authorization callback received", "ok")
                self_h.send_response(200)
                self_h.send_header("Content-Type", "text/html")
                self_h.end_headers()
                self_h.wfile.write(b"<html><body><h2>Login complete!</h2></body></html>")
            elif "signin/callback" in parsed.path or qs.get("login_option"):
                CallbackHandler.signin_callback_params = {k: v[0] for k, v in qs.items()}
                log("Signin callback received", "ok")
                self_h.send_response(200)
                self_h.send_header("Content-Type", "text/html")
                self_h.end_headers()
                self_h.wfile.write(b"<html><body><p>Redirecting...</p></body></html>")
            else:
                self_h.send_response(200)
                self_h.send_header("Content-Type", "text/html")
                self_h.end_headers()
                self_h.wfile.write(b"<html><body><p>OK</p></body></html>")

        def log_message(self_h, *args):
            pass

    # Make sure the callback port is free
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", 3128))
        sock.close()
    except OSError:
        sock.close()
        try:
            import subprocess
            r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if ":3128" in line and "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    if pid.isdigit() and int(pid) != os.getpid():
                        subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
            await asyncio.sleep(1)
        except Exception:
            pass

    callback_server = HTTPServer(("127.0.0.1", 3128), CallbackHandler)
    callback_server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_thread = threading.Thread(target=callback_server.serve_forever, daemon=True)
    srv_thread.start()
    log("Local callback server started (127.0.0.1:3128)", "ok")

    try:
        async with async_playwright() as p:
            launch_args = [
                "--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process",
                "--no-first-run",
            ]
            if headless:
                launch_args += ["--disable-gpu", "--no-sandbox",
                                "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            browser = await p.chromium.launch(headless=headless, args=launch_args)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800}, locale="en-US", user_agent=REG_UA)
            page = await context.new_page()
            await Stealth().apply_stealth_async(page)

            await page.goto(signin_url, timeout=60000)
            await page.wait_for_load_state("networkidle", timeout=30000)
            await asyncio.sleep(3)

            # Click the chosen login-method button
            if "app.kiro.dev" in page.url:
                log("On Kiro signin page, selecting login method...", "info")
                await asyncio.sleep(2)
                await _click_login_method(page, method, log)

                for _ in range(20):
                    if CallbackHandler.signin_callback_params:
                        break
                    await asyncio.sleep(1)

            # Build the OIDC authorize URL
            if CallbackHandler.signin_callback_params and not authorization_code:
                log("Building OIDC authorize URL...", "info")
                authorize_url = f"{REG_OIDC}/authorize?" + urlencode({
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": REG_REDIRECT_URI,
                    "scopes": ",".join(REG_SCOPES),
                    "state": state_val,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                })
                await page.goto(authorize_url, timeout=60000)
                await page.wait_for_load_state("networkidle", timeout=30000)
                await asyncio.sleep(3)

            # Wait for the user to complete the browser login (up to 5 minutes)
            log("Phase 3: please complete login in the browser...", "info")
            log("Waiting for user interaction (up to 5 minutes)...", "info")

            for i in range(150):
                if cancel_check and cancel_check():
                    log("User cancelled", "err")
                    await browser.close()
                    return None
                if authorization_code:
                    break
                current_url = page.url
                # Check the callback URL
                if "127.0.0.1:3128" in current_url or "localhost:3128" in current_url:
                    qs = parse_qs(urlparse(current_url).query)
                    authorization_code = qs.get("code", [""])[0]
                    if authorization_code:
                        break
                if "code=" in current_url and "code_challenge" not in current_url:
                    qs = parse_qs(urlparse(current_url).query)
                    code_val = qs.get("code", [""])[0]
                    if code_val and len(code_val) > 10:
                        authorization_code = code_val
                        break
                # Automatically click the authorize button when it appears
                if "awsapps.com" in current_url:
                    try:
                        await page.evaluate("""() => {
                            const buttons = Array.from(document.querySelectorAll('button'));
                            const visible = buttons.filter(b => b.offsetWidth > 0);
                            for (const b of visible) {
                                const t = (b.innerText || '').toLowerCase();
                                if (t.includes('allow') || t.includes('authorize') || t.includes('accept') || t.includes('confirm')) {
                                    b.click(); return;
                                }
                            }
                            if (visible.length > 0) visible[visible.length - 1].click();
                        }""")
                    except Exception:
                        pass
                if i > 0 and i % 30 == 0:
                    log(f"Still waiting... ({i*2}s)", "dbg")
                await asyncio.sleep(2)

            await browser.close()
    finally:
        callback_server.shutdown()

    # Phase 4: token exchange
    if not authorization_code:
        log("No authorization code received!", "err")
        return None

    log("Authorization code received", "ok")
    log("Phase 4: exchanging for tokens...", "info")

    token_resp = s.post(f"{REG_OIDC}/token", json={
        "clientId": client_id,
        "clientSecret": client_secret,
        "grantType": "authorization_code",
        "code": authorization_code,
        "redirectUri": REG_REDIRECT_URI,
        "codeVerifier": code_verifier,
    }, timeout=25, verify=False)

    if token_resp.status_code != 200:
        log(f"Token exchange failed: HTTP {token_resp.status_code}", "err")
        return None

    tokens = token_resp.json()
    access_token = tokens.get("accessToken", "")
    refresh_token = tokens.get("refreshToken", "")
    expires_in = tokens.get("expiresIn", 28800)

    if not access_token:
        log("Token exchange response missing accessToken", "err")
        return None

    log("Token obtained", "ok")
    log(f"expires_in: {expires_in}s", "ok")

    # Pull the user's email out of the JWT
    user_email = _extract_email_from_token(access_token)
    if not user_email:
        user_email = f"{method}_user_{secrets.token_hex(4)}"
    log(f"User: {user_email}", "ok")

    # Install the token locally
    if auto_login:
        log("Injecting token into local cache...", "info")
        persist_tokens(client_id, client_secret, access_token, refresh_token, expires_in, log)

    log("=" * 40, "ok")
    log("Login import complete!", "ok")
    log(f"  User: {user_email}", "ok")
    log("=" * 40, "ok")

    return {
        "email": user_email,
        "password": "",
        "provider": "BuilderId",
        "authMethod": "IdC",
        "region": "us-east-1",
        "clientId": client_id,
        "clientSecret": client_secret,
        "clientIdHash": _sha1_hash(client_id),
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).strftime("%Y/%m/%d %H:%M:%S"),
    }


async def _click_login_method(page, method, log):
    """Click the login-method button that matches `method` on the Kiro signin page."""
    method_selectors = {
        "google": [
            'xpath=//button[contains(text(),"Google")]',
            'xpath=//a[contains(text(),"Google")]',
        ],
        "github": [
            'xpath=//button[contains(text(),"GitHub")]',
            'xpath=//button[contains(text(),"Github")]',
            'xpath=//a[contains(text(),"GitHub")]',
        ],
        "builderid": [
            'xpath=//*[@id="layout-viewport"]/div/div/div/div[2]/div/div[1]/button[3]',
            'xpath=//button[contains(text(),"AWS Builder ID")]',
            'xpath=//button[contains(text(),"Builder ID")]',
        ],
        "iam": [
            'xpath=//button[contains(text(),"IAM Identity Center")]',
            'xpath=//button[contains(text(),"Identity Center")]',
        ],
    }

    selectors = method_selectors.get(method, method_selectors["builderid"])
    for sel in selectors:
        loc = page.locator(sel)
        try:
            if await loc.count() > 0 and await loc.first.is_visible():
                await loc.first.click()
                log(f"Clicked {method} login button", "ok")
                await asyncio.sleep(3)
                return
        except Exception:
            pass

    # Fallback
    for sel in ['xpath=//button[contains(text(),"Sign in")]',
                'xpath=//button[contains(text(),"Continue")]']:
        loc = page.locator(sel)
        try:
            if await loc.count() > 0 and await loc.first.is_visible():
                await loc.first.click()
                log("Clicked fallback login button", "ok")
                await asyncio.sleep(3)
                return
        except Exception:
            pass

    # JS fallback
    try:
        await page.evaluate("""() => {
            const btn = document.querySelector('#layout-viewport button:nth-child(3)') ||
                        document.querySelectorAll('#layout-viewport button')[2];
            if (btn) btn.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true}));
        }""")
        await asyncio.sleep(3)
    except Exception:
        pass


def _extract_email_from_token(access_token):
    """Pull the user email out of a JWT access_token."""
    try:
        payload_b64 = access_token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("email", "") or payload.get("sub", "") or payload.get("username", "")
    except Exception:
        return ""
