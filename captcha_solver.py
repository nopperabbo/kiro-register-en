"""
hCaptcha solver — uses the third-party YesCaptcha service.
Extracts the sitekey from the page, calls the YesCaptcha API,
and injects the resulting token back into the page.
"""
import asyncio
import os
import time
import httpx
from datetime import datetime
from playwright.async_api import Page

YESCAPTCHA_API_KEY = os.environ.get("YESCAPTCHA_API_KEY", "")
YESCAPTCHA_API_URL = "https://api.yescaptcha.com"


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
            # The URL may also carry a `host` param, but that's not the sitekey
            match = re.search(r'host=([^&]+)', url)
            if match:
                # host is not the sitekey, keep looking
                pass

    # Method 3: scrape it from inline scripts
    sitekey = await page.evaluate("""() => {
        // hcaptcha render arguments
        if (window.hcaptcha && window.hcaptcha._psts) {
            for (const k of Object.keys(window.hcaptcha._psts)) {
                return k;
            }
        }
        // Search inline <script> bodies
        const scripts = document.querySelectorAll('script');
        for (const s of scripts) {
            const text = s.textContent || '';
            const match = text.match(/sitekey['":\\s]+['"]([a-f0-9-]{36,})['"]/);
            if (match) return match[1];
        }
        return null;
    }""")
    return sitekey


async def _create_task(sitekey: str, page_url: str, log_fn=log) -> str | None:
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
        log_fn(f"Task created: {task_id}", "info")
        return task_id


async def _get_task_result(task_id: str, log_fn=log, timeout: int = 120) -> str | None:
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
                log_fn(f"getTaskResult error: {data.get('errorDescription', data)}", "error")
                return None
            status = data.get("status")
            if status == "ready":
                token = data.get("solution", {}).get("gRecaptchaResponse")
                log_fn(f"Token retrieved ({len(token) if token else 0} chars)", "ok")
                return token
            log_fn(f"Waiting... ({int(time.time()-start)}s)", "dbg")
    log_fn("YesCaptcha timed out", "error")
    return None


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
            // Try to grab the widget ID and set the response
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
        # Fall back to injecting inside the hcaptcha iframe
        for frame in page.frames:
            if "hcaptcha.com" in frame.url:
                try:
                    await frame.evaluate("""(token) => {
                        const ta = document.querySelector('textarea[name="h-captcha-response"]');
                        if (ta) ta.value = token;
                        // Trigger postMessage callback
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
    """
    Solve hCaptcha with YesCaptcha.

    Requires the YESCAPTCHA_API_KEY environment variable to be set.
    """
    if not YESCAPTCHA_API_KEY:
        log_fn("YESCAPTCHA_API_KEY is not set!", "error")
        return False

    log_fn("hCaptcha solver started (YesCaptcha)", "info")

    # Extract the sitekey
    sitekey = await _get_sitekey(page)
    if not sitekey:
        log_fn("Could not extract hCaptcha sitekey", "error")
        # Wait a bit and retry once
        await asyncio.sleep(3)
        sitekey = await _get_sitekey(page)
        if not sitekey:
            return False

    page_url = page.url
    log_fn(f"sitekey: {sitekey}", "info")
    log_fn(f"pageURL: {page_url[:80]}...", "info")

    for attempt in range(1, max_retries + 1):
        log_fn(f"--- Attempt {attempt}/{max_retries} ---", "info")

        # Create the task
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
            # Verify the challenge UI is gone
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

    log_fn("YesCaptcha solver failed", "error")
    return False
