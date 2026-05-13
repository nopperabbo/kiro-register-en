"""
hCaptcha solver with pluggable provider backends.

Supported providers (selected via the CAPTCHA_PROVIDER env var, default: yescaptcha):
  - yescaptcha  (https://api.yescaptcha.com)   — JSON API: /createTask + /getTaskResult
  - multibot    (https://api.multibot.cloud)   — classic 2captcha-style API: /in.php + /res.php

Both providers solve hCaptcha proxyless and return a token that is injected into
the page via the shared `_inject_token` helper.

Environment variables:
    CAPTCHA_PROVIDER      either 'yescaptcha' or 'multibot' (default 'yescaptcha')
    YESCAPTCHA_API_KEY    required when CAPTCHA_PROVIDER=yescaptcha
    MULTIBOT_API_KEY      required when CAPTCHA_PROVIDER=multibot
"""
import asyncio
import os
import time
import httpx
from datetime import datetime
from playwright.async_api import Page

# Provider config
CAPTCHA_PROVIDER = os.environ.get("CAPTCHA_PROVIDER", "yescaptcha").strip().lower()

YESCAPTCHA_API_KEY = os.environ.get("YESCAPTCHA_API_KEY", "")
YESCAPTCHA_API_URL = "https://api.yescaptcha.com"

MULTIBOT_API_KEY = os.environ.get("MULTIBOT_API_KEY", "")
MULTIBOT_API_URL = "https://api.multibot.cloud"


def log(msg, level='info'):
    ts = datetime.now().strftime('%H:%M:%S')
    print(f'[{ts}] [{level.upper():5s}] {msg}')


async def _get_sitekey(page: Page) -> str | None:
    """Extract the hCaptcha sitekey from the current page."""
    # Method 1: read it from the data-sitekey attribute
    sitekey = await page.evaluate("""() => {
        const el = document.querySelector('[data-sitekey]');
        if (el) return el.getAttribute('data-sitekey');
        // Also check sitekey inside iframe src URLs
        const iframes = document.querySelectorAll('iframe');
        for (const f of iframes) {
            const src = f.src || '';
            const match = src.match(/sitekey=([a-f0-9-]+)/);
            if (match) return match[1];
        }
        return null;
    }""")
    if sitekey:
        return sitekey

    # Method 2: pull it out of the hcaptcha iframe URL
    for frame in page.frames:
        url = frame.url
        if "hcaptcha.com" in url:
            import re
            match = re.search(r'sitekey=([a-f0-9-]+)', url)
            if match:
                return match.group(1)
            match = re.search(r'host=([^&]+)', url)
            if match:
                # host is not the sitekey, keep looking
                pass

    # Method 3: scrape it from inline scripts
    sitekey = await page.evaluate("""() => {
        if (window.hcaptcha && window.hcaptcha._psts) {
            for (const k of Object.keys(window.hcaptcha._psts)) {
                return k;
            }
        }
        const scripts = document.querySelectorAll('script');
        for (const s of scripts) {
            const text = s.textContent || '';
            const match = text.match(/sitekey['\":\\s]+['\"]([a-f0-9-]{36,})['\"]/);
            if (match) return match[1];
        }
        return null;
    }""")
    return sitekey


# ─── Provider: YesCaptcha (JSON API) ─────────────────────────────────────────

async def _yescaptcha_create_task(sitekey: str, page_url: str, log_fn=log) -> str | None:
    """Create a YesCaptcha task and return the taskId."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{YESCAPTCHA_API_URL}/createTask",
            json={
                "clientKey": YESCAPTCHA_API_KEY,
                "task": {
                    "type": "HCaptchaTaskProxyless",
                    "websiteURL": page_url,
                    "websiteKey": sitekey,
                }
            }
        )
        data = resp.json()
        if data.get("errorId", 1) != 0:
            log_fn(f"YesCaptcha createTask error: {data.get('errorDescription', data)}", "error")
            return None
        task_id = data.get("taskId")
        log_fn(f"YesCaptcha task created: {task_id}", "info")
        return task_id


async def _yescaptcha_get_result(task_id: str, log_fn=log, timeout: int = 120) -> str | None:
    """Poll for the task result and return the captcha token."""
    start = time.time()
    async with httpx.AsyncClient(timeout=30) as client:
        while time.time() - start < timeout:
            await asyncio.sleep(5)
            resp = await client.post(
                f"{YESCAPTCHA_API_URL}/getTaskResult",
                json={
                    "clientKey": YESCAPTCHA_API_KEY,
                    "taskId": task_id,
                }
            )
            data = resp.json()
            if data.get("errorId", 1) != 0:
                log_fn(f"YesCaptcha getTaskResult error: {data.get('errorDescription', data)}", "error")
                return None
            status = data.get("status")
            if status == "ready":
                token = data.get("solution", {}).get("gRecaptchaResponse")
                log_fn(f"YesCaptcha token retrieved ({len(token) if token else 0} chars)", "ok")
                return token
            log_fn(f"YesCaptcha waiting... ({int(time.time()-start)}s)", "dbg")
    log_fn("YesCaptcha timed out", "error")
    return None


# ─── Provider: Multibot (classic 2captcha-style API) ─────────────────────────

async def _multibot_submit(sitekey: str, page_url: str, log_fn=log) -> str | None:
    """Submit an hCaptcha task to Multibot /in.php and return the task id.

    Multibot's classic API expects multipart/form-data. With json=1 the response
    is JSON: {"status": 1, "request": "<task_id>"} on success,
    or {"status": 0, "request": "<ERROR_CODE>"} on failure.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        files = {
            "key": (None, MULTIBOT_API_KEY),
            "method": (None, "hcaptcha"),
            "sitekey": (None, sitekey),
            "pageurl": (None, page_url),
            "json": (None, "1"),
        }
        resp = await client.post(f"{MULTIBOT_API_URL}/in.php", files=files)
        try:
            data = resp.json()
        except Exception:
            log_fn(f"Multibot /in.php returned non-JSON: {resp.text[:200]}", "error")
            return None
        if data.get("status") != 1:
            log_fn(f"Multibot /in.php error: {data.get('request', data)}", "error")
            return None
        task_id = data.get("request")
        log_fn(f"Multibot task created: {task_id}", "info")
        return task_id


async def _multibot_get_result(task_id: str, log_fn=log, timeout: int = 120) -> str | None:
    """Poll Multibot /res.php?action=get&id=... until the token is ready.

    Response when ready:   {"status": 1, "request": "<hCaptcha token>"}
    Response while pending: {"status": 0, "request": "CAPCHA_NOT_READY"}
    """
    start = time.time()
    async with httpx.AsyncClient(timeout=30) as client:
        while time.time() - start < timeout:
            await asyncio.sleep(5)
            resp = await client.get(
                f"{MULTIBOT_API_URL}/res.php",
                params={
                    "key": MULTIBOT_API_KEY,
                    "action": "get",
                    "id": task_id,
                    "json": "1",
                },
            )
            try:
                data = resp.json()
            except Exception:
                log_fn(f"Multibot /res.php returned non-JSON: {resp.text[:200]}", "warn")
                continue
            if data.get("status") == 1:
                token = data.get("request")
                log_fn(f"Multibot token retrieved ({len(token) if token else 0} chars)", "ok")
                return token
            err = data.get("request", "")
            if err == "CAPCHA_NOT_READY":
                log_fn(f"Multibot waiting... ({int(time.time()-start)}s)", "dbg")
                continue
            log_fn(f"Multibot /res.php error: {err}", "error")
            return None
    log_fn("Multibot timed out", "error")
    return None


# ─── Dispatch ────────────────────────────────────────────────────────────────

def _active_provider() -> tuple[str, str]:
    """Resolve the configured provider and its API key.

    Returns (provider_name, api_key) where provider_name is the normalised
    selector and api_key is the key for that provider (or '' if missing).
    """
    provider = CAPTCHA_PROVIDER or "yescaptcha"
    if provider == "multibot":
        return "multibot", MULTIBOT_API_KEY
    # Default and explicit yescaptcha fall here.
    return "yescaptcha", YESCAPTCHA_API_KEY


async def _create_task(sitekey: str, page_url: str, log_fn=log) -> str | None:
    provider, _ = _active_provider()
    if provider == "multibot":
        return await _multibot_submit(sitekey, page_url, log_fn)
    return await _yescaptcha_create_task(sitekey, page_url, log_fn)


async def _get_task_result(task_id: str, log_fn=log, timeout: int = 120) -> str | None:
    provider, _ = _active_provider()
    if provider == "multibot":
        return await _multibot_get_result(task_id, log_fn, timeout)
    return await _yescaptcha_get_result(task_id, log_fn, timeout)


async def _inject_token(page: Page, token: str, log_fn=log) -> bool:
    """Inject the captcha token back into the page."""
    success = await page.evaluate("""(token) => {
        // Method 1: set the h-captcha-response textarea
        const textareas = document.querySelectorAll('textarea[name="h-captcha-response"], textarea[name="g-recaptcha-response"]');
        for (const ta of textareas) {
            ta.value = token;
            ta.innerHTML = token;
        }

        // Method 2: set hidden inputs
        const inputs = document.querySelectorAll('input[name="h-captcha-response"]');
        for (const inp of inputs) {
            inp.value = token;
        }

        // Method 3: invoke the hcaptcha callback
        if (window.hcaptcha) {
            try {
                const widgetIds = Object.keys(window.hcaptcha._psts || {});
                for (const wid of widgetIds) {
                    window.hcaptcha.setResponse(token, wid);
                }
            } catch(e) {}
        }

        // Method 4: trigger the global success callback
        if (window.onHCaptchaSuccess) {
            window.onHCaptchaSuccess(token);
            return true;
        }

        // Method 5: look up data-callback and invoke it
        const captchaEl = document.querySelector('[data-callback]');
        if (captchaEl) {
            const cbName = captchaEl.getAttribute('data-callback');
            if (window[cbName]) {
                window[cbName](token);
                return true;
            }
        }

        return textareas.length > 0 || inputs.length > 0;
    }""", token)

    if success:
        log_fn("Token injected into page", "ok")
    else:
        log_fn("Top-level injection may have failed, trying frame injection...", "warn")
        for frame in page.frames:
            if "hcaptcha.com" in frame.url:
                try:
                    await frame.evaluate("""(token) => {
                        const ta = document.querySelector('textarea[name="h-captcha-response"]');
                        if (ta) ta.value = token;
                        window.parent.postMessage(JSON.stringify({
                            source: 'hcaptcha',
                            label: 'challenge-closed',
                            contents: {event: 'challenge-passed', response: token, expiration: 120}
                        }), '*');
                    }""", token)
                    log_fn("Injected via frame postMessage", "info")
                    success = True
                except Exception as e:
                    log_fn(f"Frame injection failed: {e}", "warn")

    return success


async def solve_hcaptcha(page: Page, log_fn=log, max_retries: int = 2) -> bool:
    """Solve hCaptcha using the provider selected via CAPTCHA_PROVIDER.

    When CAPTCHA_PROVIDER=multibot, MULTIBOT_API_KEY must be set.
    When CAPTCHA_PROVIDER=yescaptcha (default), YESCAPTCHA_API_KEY must be set.
    """
    provider, api_key = _active_provider()
    if not api_key:
        log_fn(f"{provider.upper()}_API_KEY is not set!", "error")
        return False

    log_fn(f"hCaptcha solver started ({provider})", "info")

    # Extract the sitekey
    sitekey = await _get_sitekey(page)
    if not sitekey:
        log_fn("Could not extract hCaptcha sitekey", "error")
        await asyncio.sleep(3)
        sitekey = await _get_sitekey(page)
        if not sitekey:
            return False

    page_url = page.url
    log_fn(f"sitekey: {sitekey}", "info")
    log_fn(f"pageURL: {page_url[:80]}...", "info")

    for attempt in range(1, max_retries + 1):
        log_fn(f"--- {provider} attempt {attempt}/{max_retries} ---", "info")

        # Create the task via the selected provider
        task_id = await _create_task(sitekey, page_url, log_fn)
        if not task_id:
            await asyncio.sleep(3)
            continue

        # Wait for the result
        token = await _get_task_result(task_id, log_fn)
        if not token:
            continue

        # Inject the token
        injected = await _inject_token(page, token, log_fn)
        if injected:
            await asyncio.sleep(2)
            challenge_gone = True
            for frame in page.frames:
                if "hcaptcha.com" in frame.url and "frame=challenge" in frame.url:
                    for f_el in await page.query_selector_all("iframe"):
                        src = await f_el.get_attribute("src") or ""
                        if "frame=challenge" in src and await f_el.is_visible():
                            challenge_gone = False
                            break
            if challenge_gone:
                log_fn("hCaptcha solved successfully!", "ok")
                return True
            else:
                log_fn("Challenge still present after token injection, retrying...", "warn")

    log_fn(f"{provider} solver failed", "error")
    return False
