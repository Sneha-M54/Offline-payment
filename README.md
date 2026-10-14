# OfflinePay — Python Full Stack Developer Intern Assignment 2

Synthetic educational demo for offline-first payments. **No real money, real customers, or live payment rails.**

## Stack
- FastAPI + SQLite
- Ed25519 server/device signatures
- Browser Web Crypto for device key generation and token signing
- Responsive HTML/CSS/JavaScript frontend
- Docker Compose

## Run locally (Python)
Requires Python 3.11+.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```
Open http://127.0.0.1:8000

## Run with Docker
```bash
docker compose up --build
```

## Demo credentials
| Role | Username | Password |
|---|---|---|
| Customer | `alice` | `alice123` |
| Customer | `bob` | `bob123` |
| Merchant | `merchant` | `shop123` |
| Analyst | `analyst` | `analyst123` |

## Demo walkthrough
1. Log in as `alice`, register device, and add funds to reserve.
2. Issue certificate; create a token paying `merchant`.
3. Open a second browser profile/window, log in as `merchant`, paste token and click **Verify offline**, then **Sync & settle**.
4. Paste the same token again and sync; it should return the existing result idempotently.
5. Try replay/counter reuse or a payment above limit; inspect analyst flags. Log in as analyst to review flags and disputes.
6. Open a dispute from a transaction hash and decide it in the analyst console.

## Tests
```bash
pytest -q
```

## Reset demo data
Local/demo only:
```bash
curl -X POST http://127.0.0.1:8000/api/reset-demo
```
This endpoint is intentionally demo-only. Disable it (`ALLOW_DEMO_RESET=0`) before any public deployment.

## Design note
Browser generates Ed25519 key pair; private key is stored in browser local storage for this demo and never sent to the API. The backend registers only the public key. The bank signs allowance certificates and settlement receipts. Payer signs a token binding certificate, payer/device, payee, amount, nonce, counter and expiry. Payee can verify signatures in-browser while offline, then syncs the signed token. Server performs authoritative checks and stores a single settlement per token hash in SQLite.

## Threat model (summary)
- **Malicious payer:** may issue conflicting payments while offline. Online settlement enforces reserve balance and unique device/counter + nonce; later conflicting payments are flagged. Offline double spending cannot be fully prevented. The reserve is the exposure cap only if reserve accounting and settlement policy are enforced correctly.
- **Malicious payee:** can refuse to issue a receipt or submit a token to a different payee. Payee ID is signed into the token; keep a copy of token and receipt on both devices.
- **Replay:** token hash idempotency, unique nonce and device/counter constraints prevent repeated settlement. Expiry is checked during offline verification and server sync.
- **Compromised signing key:** a stolen device key can sign fraudulent tokens until the certificate expires/revocation is available. Use hardware-backed keys, short certificate lifetime and revocation in a production system.

## Limitations and important security notes
This is a 2-day assignment prototype, not production-grade banking software. Passwords are seeded in plain text, the API uses a demo `X-User` header rather than real authentication sessions, and the reset endpoint is demo-only. Browser private keys in local storage are not hardware protected. For public deployment, disable reset, use proper password hashing and session/JWT auth, HTTPS, strict CORS/CSRF policies, database migrations, durable managed storage, audit logging, and a formal review. SQLite and the current demo identity model are not suitable for live payment rails.

## Deployment
Deploy this FastAPI app as a web service (Render/Railway/Fly.io) and use a persistent disk/volume for `payments.db` and `bank_private.pem`. Set `ALLOW_DEMO_RESET=0` in production. This repo does not itself create a public URL; add your deployed URL here after deploying: **Live URL: TODO**.
