"""
wallet_harvester.py v20 — AI-Adaptive Crypto Wallet Extraction Engine
"""

import os
import re
import sys
import json
import time
import random
import string
import asyncio
import requests
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY", "")

WALLET_PATTERNS = {
    "BTC":        r"\b(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
    "ETH":        r"\b(0x[a-fA-F0-9]{40})\b",
    "USDT_TRC20": r"\b(T[A-Za-z0-9]{33})\b",
    "LTC":        r"\b(ltc1[a-zA-Z0-9]{25,62}|[LM][a-zA-Z0-9]{26,33})\b",
    "XRP":        r"\b(r[0-9a-zA-Z]{24,34})\b",
    "DOGE":       r"\b(D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{24,33})\b",
    "SOL":        r"\b([1-9A-HJ-NP-Za-km-z]{43,44})\b",
    "BNB":        r"\b(bnb1[a-zA-Z0-9]{38})\b",
}

FALSE_POSITIVE_CHECKS = {
    "SOL": lambda addr: bool(re.search(r'[g-zG-Z]', addr)),
    "BTC": lambda addr: not bool(re.match(r'^[0-9a-f]{32,}$', addr)),
    "LTC": lambda addr: not addr.isalpha(),
    "XRP": lambda addr: any(c.isdigit() for c in addr),
}

DEPOSIT_PATHS = [
    "/deposit", "/invest", "/payment", "/fund",
    "/user/deposit", "/user/invest", "/user/payment",
    "/dashboard/deposit", "/dashboard/invest", "/account/deposit",
    "/wallet/deposit", "/plans", "/packages", "/invest/plans",
    "/crypto/deposit", "/fund/deposit", "/member/deposit",
    "/?a=deposit", "/?a=invest", "/?a=payment", "/?a=wallet",
    "/?a=dashboard", "/?a=fund", "/?a=plans",
    "/?page=deposit", "/?page=invest", "/?view=deposit",
]

REGISTER_PATHS = [
    "/register", "/signup", "/sign-up", "/join", "/create-account",
    "/user/register", "/account/register", "/auth/register",
    "/en/register", "/app/register", "/member/register",
    "/?a=signup", "/?a=register", "/?a=join", "/?page=register",
]

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/user/login", "/account/login",
    "/auth/login", "/user/signin", "/en/login", "/app/login",
    "/?a=login", "/?a=signin", "/?page=login", "/member/login",
]


def generate_fake_identity() -> dict:
    first_names = ["James", "Michael", "Robert", "David", "John",
                   "Sarah", "Emma", "Lisa", "Anna", "Maria"]
    last_names  = ["Smith", "Johnson", "Williams", "Brown", "Jones",
                   "Garcia", "Miller", "Davis", "Wilson", "Taylor"]
    first    = random.choice(first_names)
    last     = random.choice(last_names)
    username = f"{first.lower()}{last.lower()}{random.randint(1000,9999)}"
    email    = f"{username}@mailinator.com"
    chars    = string.ascii_letters + string.digits
    password = "".join(random.choices(chars, k=10)) + "1Aa!"
    return {
        "first_name":  first,
        "last_name":   last,
        "full_name":   f"{first} {last}",
        "username":    username,
        "email":       email,
        "password":    password,
        "phone":       f"+1{random.randint(2000000000, 9999999999)}",
        "btc_wallet":  "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf6a",
        "eth_wallet":  "0x0000000000000000000000000000000000000001",
        "usdt_wallet": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "ltc_wallet":  "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ",
        "referral":    "",
    }


def extract_wallets_from_text(text: str) -> dict:
    wallets = {}
    for currency, pattern in WALLET_PATTERNS.items():
        matches = re.findall(pattern, text)
        valid = []
        for addr in set(matches):
            if len(addr) < 25:
                continue
            if addr.startswith("0x" + "0" * 38):
                continue
            check = FALSE_POSITIVE_CHECKS.get(currency)
            if check and not check(addr):
                continue
            valid.append(addr)
        if valid:
            wallets[currency] = valid
    return wallets


def _merge_wallets(target: dict, source: dict):
    for currency, addresses in source.items():
        if currency not in target:
            target[currency] = []
        for addr in addresses:
            if addr not in target[currency]:
                target[currency].append(addr)


async def _extract_wallets_from_page(page) -> dict:
    wallets = {}
    try:
        content = await page.content()
        _merge_wallets(wallets, extract_wallets_from_text(content))
    except Exception:
        pass
    try:
        inputs = await page.query_selector_all("input, textarea")
        for inp in inputs:
            val = await inp.get_attribute("value") or ""
            if val and len(val) > 20:
                _merge_wallets(wallets, extract_wallets_from_text(val))
    except Exception:
        pass
    try:
        els = await page.query_selector_all("[data-clipboard-text], [data-copy], [data-value]")
        for el in els:
            for attr in ["data-clipboard-text", "data-copy", "data-value"]:
                val = await el.get_attribute(attr) or ""
                if val:
                    _merge_wallets(wallets, extract_wallets_from_text(val))
    except Exception:
        pass
    return wallets


async def _get_ai_strategy(html: str, url: str, task: str) -> dict:
    """Use OpenAI to identify exact form field selectors."""
    api_key = OPENAI_API_KEY or ANTHROPIC_API_KEY
    if not api_key:
        return {}

    html_snippet = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL)
    html_snippet = re.sub(r'<style[^>]*>.*?</style>', '', html_snippet, flags=re.DOTALL)
    html_snippet = html_snippet[:6000]

    prompt = f"""You are analyzing an HYIP cryptocurrency scam website for law enforcement investigation.
URL: {url}
Task: {task}

HTML:
{html_snippet}

Return ONLY valid JSON with exact CSS selectors found in the HTML above:
{{
  "fields": {{
    "full_name": "selector or null",
    "username": "selector or null",
    "email": "selector or null",
    "confirm_email": "selector or null",
    "password": "selector or null",
    "confirm_password": "selector or null",
    "phone": "selector or null",
    "btc_wallet": "selector or null",
    "usdt_wallet": "selector or null",
    "eth_wallet": "selector or null",
    "ltc_wallet": "selector or null",
    "amount": "selector or null",
    "plan": "selector or null",
    "payment_btc": "selector or null"
  }},
  "submit": "selector for submit button",
  "notes": "brief notes"
}}"""

    try:
        if OPENAI_API_KEY:
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}",
                         "Content-Type": "application/json"},
                json={"model": "gpt-4o-mini", "max_tokens": 800,
                      "messages": [{"role": "user", "content": prompt}],
                      "response_format": {"type": "json_object"}},
                timeout=20
            )
            if r.status_code == 200:
                return json.loads(r.json()["choices"][0]["message"]["content"])
    except Exception:
        pass

    try:
        if ANTHROPIC_API_KEY:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_API_KEY,
                         "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": "claude-haiku-4-5-20251001", "max_tokens": 800,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=20
            )
            if r.status_code == 200:
                text = r.json()["content"][0]["text"].strip()
                text = re.sub(r'^```json\s*|\s*```$', '', text)
                return json.loads(text)
    except Exception:
        pass

    return {}


async def _scan_and_fill_form(page, identity: dict, task: str) -> bool:
    """
    The real fix: scan ALL input fields on the page, map them by
    name/placeholder/type, and fill everything intelligently.
    No hardcoded selectors. Works on ANY site.
    """
    try:
        inputs = await page.query_selector_all("input:not([type='hidden']):not([type='submit']):not([type='button']), select, textarea")
    except Exception:
        return False

    filled = 0
    for inp in inputs:
        try:
            if not await inp.is_visible():
                continue

            name        = (await inp.get_attribute("name") or "").lower()
            placeholder = (await inp.get_attribute("placeholder") or "").lower()
            itype       = (await inp.get_attribute("type") or "text").lower()
            id_attr     = (await inp.get_attribute("id") or "").lower()
            combined    = f"{name} {placeholder} {id_attr}"

            value = None

            # Password fields
            if itype == "password":
                value = identity["password"]

            # Email fields
            elif itype == "email" or any(kw in combined for kw in ["email"]):
                if any(kw in combined for kw in ["confirm", "retype", "repeat", "verify", "again"]):
                    value = identity["email"]
                else:
                    value = identity["email"]

            # Name fields
            elif any(kw in combined for kw in ["full_name", "fullname", "user_name"]) and "user" in combined:
                value = identity["full_name"]
            elif any(kw in combined for kw in ["username", "user_username", "login"]) and not any(kw in combined for kw in ["email", "password"]):
                value = identity["username"]
            elif any(kw in combined for kw in ["first", "fname"]):
                value = identity["first_name"]
            elif any(kw in combined for kw in ["last", "lname", "surname"]):
                value = identity["last_name"]
            elif any(kw in combined for kw in ["name"]) and "user" in combined:
                value = identity["full_name"]

            # Phone
            elif itype == "tel" or any(kw in combined for kw in ["phone", "mobile", "cell"]):
                value = identity["phone"]

            # Wallet fields
            elif any(kw in combined for kw in ["bitcoin", "btc", "wallet_btc", "1000"]):
                value = identity["btc_wallet"]
            elif any(kw in combined for kw in ["usdt", "trc20", "tether", "wallet_usdt", "1001"]):
                value = identity["usdt_wallet"]
            elif any(kw in combined for kw in ["ethereum", "eth", "wallet_eth", "1002"]):
                value = identity["eth_wallet"]
            elif any(kw in combined for kw in ["litecoin", "ltc", "wallet_ltc"]):
                value = identity["ltc_wallet"]
            elif any(kw in combined for kw in ["wallet", "address", "crypto"]):
                value = identity["btc_wallet"]

            # Amount
            elif any(kw in combined for kw in ["amount", "sum", "invest"]):
                value = "50"

            # Referral
            elif any(kw in combined for kw in ["referral", "ref", "upline", "sponsor", "refer"]):
                value = ""

            # Bot check (common in HYIP scripts)
            elif any(kw in combined for kw in ["botcheck", "bot_check", "human"]):
                value = str(random.randint(1000, 9999))

            if value is not None:
                tag = await inp.evaluate("el => el.tagName.toLowerCase()")
                if tag == "select":
                    try:
                        options = await inp.query_selector_all("option")
                        for opt in options:
                            opt_val = await opt.get_attribute("value") or ""
                            if opt_val and opt_val != "0":
                                await inp.select_option(opt_val)
                                filled += 1
                                break
                    except Exception:
                        pass
                else:
                    await inp.fill(str(value))
                    filled += 1

        except Exception:
            continue

    # Check all checkboxes
    try:
        for cb in await page.query_selector_all('input[type="checkbox"]'):
            try:
                if not await cb.is_checked():
                    await cb.check()
            except Exception:
                pass
    except Exception:
        pass

    return filled > 0


async def _submit_form(page) -> bool:
    for sel in [
        'button[type="submit"]', 'input[type="submit"]',
        'button:has-text("Register")', 'button:has-text("Sign Up")',
        'button:has-text("Create Account")', 'button:has-text("Join")',
        'button:has-text("Login")', 'button:has-text("Sign In")',
        'button:has-text("Submit")', 'button:has-text("Continue")',
        'button:has-text("Make Deposit")', 'button:has-text("Deposit")',
        'button:has-text("Invest")', 'button:has-text("Proceed")',
        '.btn-primary', '.btn-submit', '#submit', '#login-btn',
        'button[class*="submit"]', 'button[class*="register"]',
        'button[class*="login"]', 'a[class*="submit"]',
    ]:
        try:
            btn = await page.query_selector(sel)
            if btn and await btn.is_visible():
                await btn.click()
                await page.wait_for_timeout(3000)
                return True
        except Exception:
            continue
    return False


async def _check_logged_in(page) -> bool:
    try:
        content = await page.content()
        content_lower = content.lower()
        url = page.url.lower()
        has_logout = any(kw in content_lower for kw in
                         ["logout", "log out", "sign out", "signout"])
        if not has_logout:
            return False
        if any(kw in url for kw in ["dashboard", "account", "member", "home", "portal"]):
            return True
        auth_indicators = ["deposit", "withdraw", "balance", "investment", "portfolio"]
        return sum(1 for kw in auth_indicators if kw in content_lower) >= 2
    except Exception:
        return False


async def _attempt_registration(page, base_url: str, identity: dict) -> bool:
    for path in REGISTER_PATHS:
        try:
            r = await page.goto(base_url + path,
                                wait_until="domcontentloaded", timeout=15000)
            if not r or r.status in (404, 403, 500):
                continue
            content = await page.content()
            if "password" not in content.lower():
                continue

            filled = await _scan_and_fill_form(page, identity, "register")
            if not filled:
                continue

            await _submit_form(page)
            await page.wait_for_timeout(2000)
            print(f"  [harvester] Registration attempted at {path}")

            if await _check_logged_in(page):
                print(f"  [harvester] Auto-logged in after registration")
                return True
            return True
        except Exception:
            continue
    return False


async def _attempt_login(page, base_url: str, identity: dict) -> bool:
    for path in LOGIN_PATHS:
        try:
            r = await page.goto(base_url + path,
                                wait_until="domcontentloaded", timeout=15000)
            if not r or r.status in (404, 403, 500):
                continue
            content = await page.content()
            if "password" not in content.lower():
                continue

            filled = await _scan_and_fill_form(page, identity, "login")
            if not filled:
                continue

            await _submit_form(page)
            await page.wait_for_timeout(3000)

            if await _check_logged_in(page):
                print(f"  [harvester] Login successful via {path}")
                return True
        except Exception:
            continue
    return False


async def _submit_deposit_form(page, base_url: str, output_dir: str, domain: str) -> dict:
    wallets = {}
    for path in DEPOSIT_PATHS:
        try:
            r = await page.goto(base_url + path,
                                wait_until="domcontentloaded", timeout=15000)
            if not r or r.status in (404, 403, 500):
                continue

            await page.wait_for_timeout(2000)
            content = await page.content()

            if not any(kw in content.lower() for kw in
                       ["deposit", "invest", "plan", "amount", "payment", "bitcoin"]):
                continue

            # Select first plan in any dropdown
            try:
                selects = await page.query_selector_all("select")
                for sel in selects:
                    options = await sel.query_selector_all("option")
                    for opt in options:
                        val = await opt.get_attribute("value") or ""
                        if val and val not in ("0", "", "select"):
                            await sel.select_option(val)
                            break
            except Exception:
                pass

            # Fill amount
            try:
                for amt_sel in ['input[name="amount"]', 'input[placeholder*="amount" i]',
                                'input[id*="amount" i]']:
                    amt = await page.query_selector(amt_sel)
                    if amt and await amt.is_visible():
                        await amt.fill("50")
                        break
            except Exception:
                pass

            # Select first radio (payment type)
            try:
                radios = await page.query_selector_all('input[type="radio"]')
                if radios:
                    await radios[0].click()
            except Exception:
                pass

            # Try each payment value pattern
            for val in ["process_1000", "process_1001", "1000", "btc", "bitcoin"]:
                try:
                    r2 = await page.query_selector(f'input[value="{val}"]')
                    if r2:
                        await r2.click()
                        break
                except Exception:
                    pass

            await _submit_form(page)
            await page.wait_for_timeout(4000)

            wallets = await _extract_wallets_from_page(page)
            if wallets:
                ss = f"{output_dir}/{domain.replace('.','_')}_deposit_reveal.png"
                await page.screenshot(path=ss, full_page=True)
                print(f"  [harvester] Deposit reveal screenshot saved")
                return wallets

        except Exception:
            continue
    return wallets


async def harvest_wallets(domain: str, output_dir: str = "outputs") -> dict:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed", "wallets": {}}

    base_url = f"https://{domain}"
    identity = generate_fake_identity()
    Path(output_dir).mkdir(exist_ok=True)

    all_wallets          = {}
    screenshots          = []
    pages_visited        = []
    registration_success = False
    login_success        = False

    print(f"\n  [harvester] Starting v20 adaptive harvester for {domain}")
    print(f"  [harvester] Identity: {identity['email']}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox",
                  "--disable-blink-features=AutomationControlled"],
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ignore_https_errors=True,
        )
        page = await context.new_page()

        # Phase 1: Homepage
        try:
            await page.goto(base_url, wait_until="networkidle", timeout=30000)
            wallets = await _extract_wallets_from_page(page)
            _merge_wallets(all_wallets, wallets)
            pages_visited.append(base_url)
            ss = f"{output_dir}/{domain.replace('.','_')}_homepage.png"
            await page.screenshot(path=ss, full_page=True)
            screenshots.append(ss)
            print(f"  [harvester] Homepage loaded")
            if await _check_logged_in(page):
                login_success = True
        except Exception as e:
            print(f"  [harvester] Homepage failed: {e}")

        # Phase 2: Register
        if not login_success:
            registration_success = await _attempt_registration(page, base_url, identity)
            if registration_success:
                ss = f"{output_dir}/{domain.replace('.','_')}_post_register.png"
                await page.screenshot(path=ss, full_page=True)
                screenshots.append(ss)
                if await _check_logged_in(page):
                    login_success = True
                else:
                    login_success = await _attempt_login(page, base_url, identity)

        # Phase 3: Login if needed
        if not login_success:
            login_success = await _attempt_login(page, base_url, identity)
            if not login_success:
                print(f"  [harvester] Could not authenticate — scanning public pages only")

        # Phase 4: Scan deposit paths
        print(f"  [harvester] Scanning paths (authenticated={login_success})...")
        for path in DEPOSIT_PATHS:
            try:
                r = await page.goto(base_url + path,
                                    wait_until="domcontentloaded", timeout=15000)
                if not r or r.status in (404, 403, 500):
                    continue
                await page.wait_for_timeout(2000)
                wallets = await _extract_wallets_from_page(page)
                if wallets:
                    _merge_wallets(all_wallets, wallets)
                    pages_visited.append(base_url + path)
                    print(f"  [harvester] WALLETS on {path}: {wallets}")
                    ss = f"{output_dir}/{domain.replace('.','_')}{path.replace('/','_').replace('?','_').replace('=','_')}.png"
                    await page.screenshot(path=ss, full_page=True)
                    screenshots.append(ss)
                try:
                    qr = await page.query_selector_all("img[src*='qr' i], canvas[class*='qr' i]")
                    if qr:
                        ss = f"{output_dir}/{domain.replace('.','_')}{path.replace('/','_')}_qr.png"
                        await page.screenshot(path=ss, full_page=True)
                        screenshots.append(ss)
                        print(f"  [harvester] QR code detected on {path}")
                except Exception:
                    pass
            except Exception:
                continue

        # Phase 5: Submit deposit form if still no wallets
        if login_success and not all_wallets:
            print(f"  [harvester] Attempting deposit form submission...")
            try:
                deposit_wallets = await _submit_deposit_form(
                    page, base_url, output_dir, domain
                )
                if deposit_wallets:
                    _merge_wallets(all_wallets, deposit_wallets)
                    print(f"  [harvester] WALLETS via deposit form: {deposit_wallets}")
            except Exception as e:
                print(f"  [harvester] Deposit form failed: {e}")

        await browser.close()

    total = sum(len(v) for v in all_wallets.values())
    print(f"  [harvester] Done — {total} wallets, authenticated={login_success}")

    # Phase 6: Blockchain
    blockchain_results = {}
    total_usd = 0.0
    if all_wallets:
        print(f"  [harvester] Tracing on blockchain...")
        try:
            from scripts.blockchain import analyze_wallet
            for currency, addresses in all_wallets.items():
                blockchain_results[currency] = []
                for addr in addresses:
                    result = analyze_wallet(currency, addr)
                    blockchain_results[currency].append(result)
                    usd = result.get("total_received_usd", 0) or 0
                    total_usd += usd
                    if usd > 0:
                        print(f"  [harvester] {currency} {addr[:16]}... → ${usd:,.2f}")
        except Exception as e:
            print(f"  [harvester] Blockchain error: {e}")

    if total_usd > 0:
        print(f"  [harvester] TOTAL VICTIM LOSSES: ${total_usd:,.2f}")

    return {
        "wallets":                all_wallets,
        "wallet_count":           total,
        "blockchain":             blockchain_results,
        "total_usd":              total_usd,
        "pages_visited":          pages_visited,
        "screenshots":            screenshots,
        "registration_attempted": registration_success,
        "login_success":          login_success,
        "fake_email":             identity["email"],
        "timestamp":              datetime.now().isoformat(),
    }


def harvest_wallets_sync(domain: str, output_dir: str = "outputs") -> dict:
    return asyncio.run(harvest_wallets(domain, output_dir))


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "vevrecapital.net"
    result = harvest_wallets_sync(domain)
    print(json.dumps(result, indent=2, default=str))
