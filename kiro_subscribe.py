"""
Kiro Pro subscription module — retrieves the one-time Stripe checkout URL
for the $0 Pro trial plan.

After registration, the initial subscription payment URL is single-use:
once the browser tab is closed, the $0 trial window is gone. This module
talks to the CodeWhisperer Runtime API directly to fetch that Stripe URL.

API flow:
1. POST /listAvailableSubscriptions → enumerate available plans (including subscriptionType)
2. POST /CreateSubscriptionToken  → obtain the one-shot Stripe checkout URL (encodedVerificationUrl)

Dependencies: requests
"""
import json
import uuid
import requests
from datetime import datetime


CODEWHISPERER_ENDPOINT = "https://q.us-east-1.amazonaws.com"

FIXED_PROFILE_ARNS = {
    "BuilderId": "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX",
    "Github": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
    "Google": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
}


def _headers(access_token):
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "x-amz-target": "com.amazonaws.codewhisperer",
    }


def list_available_subscriptions(access_token, profile_arn, log=print):
    """
    Enumerate the subscription plans available to this account.

    Returns:
        dict: {"ok": True, "data": {...}} on success, or {"ok": False, "error": {...}} on failure.
    """
    url = f"{CODEWHISPERER_ENDPOINT}/listAvailableSubscriptions"
    payload = {"profileArn": profile_arn}

    log("Querying available subscription plans...", "info")
    try:
        resp = requests.post(url, json=payload, headers=_headers(access_token),
                             timeout=30, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            plans = data.get("subscriptionPlans", [])
            disclaimer = data.get("disclaimer", [])
            log(f"Received {len(plans)} plans", "ok")
            for p in plans:
                title = p.get("description", {}).get("title", "Unknown")
                pricing = p.get("pricing", {})
                amount = pricing.get("amount", -1)
                currency = pricing.get("currency", "")
                sub_type = p.get("qSubscriptionType", "")
                log(f"  [{sub_type}] {title} - {amount} {currency}", "dbg")
            return {"ok": True, "data": data, "plans": plans, "disclaimer": disclaimer}
        else:
            error_body = resp.text[:500]
            log(f"Plan query failed: HTTP {resp.status_code} - {error_body}", "error")
            return {"ok": False, "error": {"status": resp.status_code, "body": error_body}}
    except Exception as e:
        log(f"Plan query exception: {e}", "error")
        return {"ok": False, "error": {"message": str(e)}}


def create_subscription_token(access_token, profile_arn, subscription_type,
                              success_url=None, cancel_url=None, log=print):
    """
    Create a subscription token and retrieve a one-shot Stripe checkout URL.

    Args:
        access_token: a valid accessToken
        profile_arn: the CodeWhisperer profileArn
        subscription_type: plan identifier (e.g. "KIRO_PRO")
        success_url: optional post-payment redirect URL
        cancel_url: optional cancel-payment redirect URL

    Returns:
        dict: {"ok": True, "url": "...", "token": "...", "status": "..."} on success,
              otherwise {"ok": False, ...}
    """
    url = f"{CODEWHISPERER_ENDPOINT}/CreateSubscriptionToken"
    payload = {
        "provider": "STRIPE",
        "subscriptionType": subscription_type,
        "profileArn": profile_arn,
        "clientToken": str(uuid.uuid4()),
    }
    if success_url:
        payload["successUrl"] = success_url
    if cancel_url:
        payload["cancelUrl"] = cancel_url

    log(f"Creating subscription token (type={subscription_type})...", "info")
    try:
        resp = requests.post(url, json=payload, headers=_headers(access_token),
                             timeout=30, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            encoded_url = data.get("encodedVerificationUrl", "")
            status = data.get("status", "")
            token = data.get("token", "")
            if encoded_url:
                log(f"Checkout URL retrieved (status={status})", "ok")
                log(f"[IMPORTANT] One-shot checkout URL: {encoded_url}", "warn")
            else:
                log(f"Response had no encodedVerificationUrl, status={status}", "warn")
            return {
                "ok": True,
                "url": encoded_url,
                "token": token,
                "status": status,
                "raw": data,
            }
        else:
            error_body = resp.text[:500]
            log(f"CreateSubscriptionToken failed: HTTP {resp.status_code} - {error_body}", "error")
            return {"ok": False, "error": {"status": resp.status_code, "body": error_body}}
    except Exception as e:
        log(f"CreateSubscriptionToken exception: {e}", "error")
        return {"ok": False, "error": {"message": str(e)}}


def fetch_checkout_page(payment_url, log=print):
    """
    Render the Stripe checkout page with Playwright and decide whether this is a $0 trial.

    Returns:
        dict: {is_free_trial, total_due_today, elements} or None on failure.
    """
    import asyncio

    async def _fetch():
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            log("playwright not installed, skipping element capture", "warn")
            return None

        log("Rendering checkout page...", "info")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
                page = await browser.new_page(
                    viewport={"width": 1280, "height": 900}, locale="en-US"
                )
                await page.goto(payment_url, timeout=60000, wait_until="domcontentloaded")
                await asyncio.sleep(10)

                elements = await page.evaluate("""() => {
                    const result = {prices: [], headers: [], buttons: [], inputs: []};

                    document.querySelectorAll('*').forEach(el => {
                        const text = (el.innerText || el.textContent || '').trim();
                        if (text && text.length < 200 && el.children.length === 0) {
                            if (/\\$[\\d,.]+|free|trial|0\\.00|total|subtotal|per month|due today/i.test(text)) {
                                result.prices.push({tag: el.tagName, text: text});
                            }
                        }
                    });

                    document.querySelectorAll('h1, h2, h3, h4').forEach(el => {
                        const text = (el.innerText || '').trim();
                        if (text) result.headers.push({tag: el.tagName, text: text});
                    });

                    document.querySelectorAll('button, [role="button"], input[type="submit"]').forEach(btn => {
                        if (btn.offsetWidth > 0) {
                            result.buttons.push({
                                text: (btn.innerText || btn.value || '').trim().substring(0, 100),
                                disabled: btn.disabled || false,
                            });
                        }
                    });

                    document.querySelectorAll('input, select').forEach(inp => {
                        if (inp.offsetWidth > 0) {
                            result.inputs.push({
                                type: inp.type || '', name: inp.name || '',
                                placeholder: inp.placeholder || '',
                            });
                        }
                    });

                    return result;
                }""")

                await browser.close()

                # Decide whether this is a $0 trial — extract the "due today" amount
                import re
                all_price_text = " ".join(p["text"] for p in elements.get("prices", []))
                total_due = ""
                is_free = False

                # Strategy 1: look at price elements that mention "total" / "due today"
                for p in elements.get("prices", []):
                    txt = p["text"]
                    m = re.search(r'\$([\d,.]+)', txt)
                    if m and ("total" in txt.lower() or "due today" in txt.lower()):
                        total_due = f"${m.group(1)}"
                        if float(m.group(1).replace(",", "")) == 0:
                            is_free = True
                        break

                # Strategy 2: find the amount element that follows a "total"/"due today" label
                if not total_due:
                    prices = elements.get("prices", [])
                    for i, p in enumerate(prices):
                        txt = p["text"].lower()
                        if "total" in txt or "due today" in txt:
                            for pi in prices[i:]:
                                m = re.search(r'\$([\d,.]+)', pi["text"])
                                if m:
                                    total_due = f"${m.group(1)}"
                                    if float(m.group(1).replace(",", "")) == 0:
                                        is_free = True
                                    break
                            break

                # Strategy 3: fallback — search the whole page text for $0.00
                if not total_due:
                    if "$0.00" in all_price_text:
                        is_free = True
                        total_due = "$0.00"
                    else:
                        # Any amount is better than none
                        m = re.search(r'\$([\d,.]+)', all_price_text)
                        if m:
                            total_due = f"${m.group(1)}"
                            if float(m.group(1).replace(",", "")) == 0:
                                is_free = True

                log(f"  Due today: {total_due}", "info")

                return {
                    "is_free_trial": is_free,
                    "total_due_today": total_due,
                    "elements": elements,
                }
        except Exception as e:
            log(f"Checkout page capture failed: {e}", "error")
            return None

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(lambda: asyncio.run(_fetch())).result(timeout=90)
        else:
            return asyncio.run(_fetch())
    except Exception:
        return asyncio.run(_fetch())


async def fetch_checkout_page_async(payment_url, log=print):
    """Async version of fetch_checkout_page — awaitable directly from async callers."""
    import asyncio
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log("playwright not installed, skipping element capture", "warn")
        return None

    import re

    log("Rendering checkout page...", "info")
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            page = await browser.new_page(
                viewport={"width": 1280, "height": 900}, locale="en-US"
            )
            await page.goto(payment_url, timeout=60000, wait_until="domcontentloaded")
            await asyncio.sleep(10)

            elements = await page.evaluate("""() => {
                const result = {prices: [], headers: [], buttons: [], inputs: []};
                document.querySelectorAll('*').forEach(el => {
                    const text = (el.innerText || el.textContent || '').trim();
                    if (text && text.length < 200 && el.children.length === 0) {
                        if (/\\$[\\d,.]+|free|trial|0\\.00|total|subtotal|per month|due today/i.test(text)) {
                            result.prices.push({tag: el.tagName, text: text});
                        }
                    }
                });
                document.querySelectorAll('h1, h2, h3, h4').forEach(el => {
                    const text = (el.innerText || '').trim();
                    if (text) result.headers.push({tag: el.tagName, text: text});
                });
                return result;
            }""")

            await browser.close()

            all_price_text = " ".join(item["text"] for item in elements.get("prices", []))
            total_due = ""
            is_free = False

            for item in elements.get("prices", []):
                txt = item["text"]
                m = re.search(r'\$([\d,.]+)', txt)
                if m and ("total" in txt.lower() or "due today" in txt.lower()):
                    total_due = f"${m.group(1)}"
                    if float(m.group(1).replace(",", "")) == 0:
                        is_free = True
                    break

            if not total_due:
                prices = elements.get("prices", [])
                for i, item in enumerate(prices):
                    txt = item["text"].lower()
                    if "total" in txt or "due today" in txt:
                        for pi in prices[i:]:
                            m = re.search(r'\$([\d,.]+)', pi["text"])
                            if m:
                                total_due = f"${m.group(1)}"
                                if float(m.group(1).replace(",", "")) == 0:
                                    is_free = True
                                break
                        break

            if not total_due:
                if "$0.00" in all_price_text:
                    is_free = True
                    total_due = "$0.00"
                else:
                    m = re.search(r'\$([\d,.]+)', all_price_text)
                    if m:
                        total_due = f"${m.group(1)}"
                        if float(m.group(1).replace(",", "")) == 0:
                            is_free = True

            log(f"  Due today: {total_due}", "info")

            return {
                "is_free_trial": is_free,
                "total_due_today": total_due,
                "elements": elements,
            }
    except Exception as e:
        log(f"Checkout page capture failed: {e}", "error")
        return None


def subscribe_pro(access_token, profile_arn=None, provider="BuilderId",
                  subscription_type=None, log=print):
    """
    Complete Pro subscription flow: enumerate plans → fetch checkout URL.

    Args:
        access_token: a valid accessToken
        profile_arn: CodeWhisperer profileArn (defaults derived from `provider` if empty)
        provider: auth provider (BuilderId / Github / Google)
        subscription_type: specific plan ID; if None, the Pro plan is auto-selected
        log: log callback

    Returns:
        dict with payment_url, plans, subscription_type, timestamp, or None on failure.
    """
    if not profile_arn:
        profile_arn = FIXED_PROFILE_ARNS.get(provider, FIXED_PROFILE_ARNS["BuilderId"])

    log("=" * 50, "ok")
    log("Starting Pro subscription flow", "info")
    log(f"  Provider: {provider}", "info")
    log(f"  ProfileArn: {profile_arn}", "info")
    log("=" * 50, "ok")

    # Step 1: enumerate available plans
    plans_result = list_available_subscriptions(access_token, profile_arn, log)
    if not plans_result["ok"]:
        log("Failed to fetch plan list, aborting flow", "error")
        return None

    plans = plans_result["plans"]

    # Step 2: pick a Pro plan
    if not subscription_type:
        # Auto-select a plan containing "PRO" (excluding PRO_PLUS and POWER)
        for plan in plans:
            st = plan.get("qSubscriptionType", "")
            if "PRO" in st.upper() and "PLUS" not in st.upper() and "POWER" not in st.upper():
                subscription_type = st
                break
        if not subscription_type and plans:
            # If no PRO plan exists, take the first non-FREE one
            for plan in plans:
                st = plan.get("qSubscriptionType", "")
                if "FREE" not in st.upper():
                    subscription_type = st
                    break

    if not subscription_type:
        log("No Pro plan available", "error")
        return {"ok": False, "plans": plans, "error": "no_pro_plan"}

    log(f"Selected plan: {subscription_type}", "ok")

    # Step 3: fetch the checkout URL
    token_result = create_subscription_token(
        access_token, profile_arn, subscription_type, log=log
    )
    if not token_result["ok"]:
        log("Failed to obtain checkout URL", "error")
        return {"ok": False, "plans": plans, "error": token_result.get("error")}

    payment_url = token_result["url"]

    # Step 4: render the checkout page and decide if this is a $0 trial
    page_info = fetch_checkout_page(payment_url, log=log)

    log("=" * 50, "ok")
    log("Pro subscription flow complete", "ok")
    log(f"  Plan: {subscription_type}", "info")
    log(f"  Checkout URL: {payment_url}", "warn")
    if page_info:
        log(f"  $0 trial: {page_info.get('is_free_trial', 'unknown')}", "info")
        log(f"  Due today: {page_info.get('total_due_today', 'unknown')}", "info")
    log("  [WARNING] This URL is single-use — closing the tab forfeits the $0 trial", "warn")
    log("=" * 50, "ok")

    return {
        "ok": True,
        "payment_url": payment_url,
        "subscription_type": subscription_type,
        "token": token_result.get("token"),
        "status": token_result.get("status"),
        "is_free_trial": page_info.get("is_free_trial") if page_info else None,
        "total_due_today": page_info.get("total_due_today") if page_info else None,
        "page_elements": page_info.get("elements") if page_info else None,
        "plans": plans,
        "disclaimer": plans_result.get("disclaimer", []),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─── Convenience CLI entry point ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python kiro_subscribe.py <access_token> [profile_arn]")
        sys.exit(1)

    token = sys.argv[1]
    pa = sys.argv[2] if len(sys.argv) > 2 else None

    def _log(msg, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [{level.upper():5s}] {msg}")

    result = subscribe_pro(token, profile_arn=pa, log=_log)
    if result and result.get("ok"):
        print("\n" + "=" * 60)
        print(f"Checkout URL (single-use, save it): {result['payment_url']}")
        print("=" * 60)
        out_path = f"subscribe_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"Full result saved: {out_path}")
    else:
        print("Subscription flow failed")
        if result:
            print(json.dumps(result, ensure_ascii=False, indent=2))
