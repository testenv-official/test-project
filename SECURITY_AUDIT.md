# Security Audit Report — SHKeeper

**Date:** 2026-02-23
**Scope:** Full source code review of shkeeper application
**Severity Ratings:** CRITICAL / HIGH / MEDIUM

---

## CRITICAL FINDINGS

### 1. Session Forgery via Hardcoded SECRET_KEY

- **File:** `shkeeper/__init__.py:60`
- **Code:** `SECRET_KEY="dev"`
- **Impact:** Full authentication bypass including 2FA. An attacker can forge admin session cookies.
- **Proof:** `flask-unsign --sign --cookie '{"user_id": 1}' --secret 'dev'`
- **Fix:** Generate a cryptographically random SECRET_KEY and store it outside source code.

### 2. SSRF via callback_url

- **Files:** `shkeeper/models.py:429`, `shkeeper/callback.py:41-46, 118-123`
- **Impact:** Server makes HTTP requests to attacker-controlled or internal URLs. Cloud metadata theft, internal network scanning.
- **Vector:** `callback_url` from `payment_request` API is stored and used in `requests.post()` without host validation.
- **Fix:** Validate callback_url against an allowlist or block private/internal IP ranges.

### 3. Wallet Decryption Key Exposed via API

- **File:** `shkeeper/api_v1.py:537-541`
- **Code:** `"key": wallet_encryption.key()` returned in plaintext
- **Impact:** Full wallet compromise. Attacker obtains encryption key for all wallet data.
- **Prerequisite:** Backend key header (defaults to "shkeeper")
- **Fix:** Never expose the encryption key via API. Remove or restrict this endpoint.

### 4. Default Backend Key Bypasses Authentication

- **File:** `shkeeper/api_v1.py:414, 445`
- **Code:** `environ.get("SHKEEPER_BTC_BACKEND_KEY", "shkeeper")`
- **Impact:** Unauthenticated access to walletnotify (inject fake transactions), payoutnotify, and decrypt endpoints.
- **Fix:** Require explicit configuration with no default fallback. Fail closed if not set.

---

## HIGH FINDINGS

### 5. Mass Assignment in Exchange Rate Update

- **File:** `shkeeper/wallet.py:196-213`
- **Impact:** Arbitrary database column writes on ExchangeRate model via crafted form fields.
- **Vector:** `rates__<symbol>__<any_column>` form fields passed directly to SQLAlchemy `.update()`.
- **Fix:** Whitelist allowed fields before passing to `.update()`.

### 6. No CSRF Protection

- **Impact:** All state-changing POST endpoints vulnerable to cross-site request forgery.
- **Verification:** Zero results searching for csrf, CSRFProtect, WTF, csrf_token.
- **Fix:** Implement Flask-WTF CSRF protection.

### 7. No Brute Force Protection on Login/2FA

- **File:** `shkeeper/auth.py:138-174, 199-247`
- **Impact:** Unlimited login and 2FA verification attempts. Credential and TOTP brute forcing.
- **Fix:** Implement rate limiting and account lockout.

### 8. Stack Traces in API Responses

- **File:** `shkeeper/api_v1.py` (lines 133, 191, 508, 646, 679, 696, 748)
- **Code:** `"traceback": traceback.format_exc()`
- **Impact:** Internal file paths, library versions, and code logic exposed to API consumers.
- **Fix:** Remove traceback from production responses. Log internally only.

### 9. Dynamic Model Attribute Filtering

- **File:** `shkeeper/wallet.py:251-259, 396-399`
- **Impact:** Blind data extraction on any model column via query parameter probing.
- **Fix:** Whitelist allowed filter parameters.

### 10. Default Credentials Across All Services

- **Files:** `bitcoin_like_crypto.py:153-155`, `ethereum.py:22-23`, `tron_token.py:29-31`, `auth.py:36-37`, `monero.py:32-48`, `wallet_encryption.py:25`
- **Impact:** All backend services use `shkeeper:shkeeper` by default.
- **Fix:** Require explicit credential configuration. Fail if not set.

---

## MEDIUM FINDINGS

### 11. NoneType Crash in Session Loader

- **File:** `shkeeper/auth.py:113-114`
- **Impact:** Unhandled NoneType if session references a deleted user. Causes 500 errors.
- **Fix:** Add null check: `if user and user.passhash:`
