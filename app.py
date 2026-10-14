import os, json, sqlite3, hashlib, secrets, base64, time
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

DB = os.getenv("DB_PATH", "payments.db")
KEY_FILE = os.getenv("BANK_KEY_FILE", "bank_private.pem")
app = FastAPI(title="OfflinePay Demo", version="1.0.0")
os.makedirs("static", exist_ok=True)

def now():
    return datetime.now(timezone.utc)

def iso(dt=None):
    return (dt or now()).isoformat()

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def bank_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = Ed25519PrivateKey.generate()
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try: os.chmod(KEY_FILE, 0o600)
    except OSError: pass
    return key

BANK = bank_key()

def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def canonical(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
def public_pem(key):
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL, balance INTEGER NOT NULL DEFAULT 0, account_age_days INTEGER NOT NULL DEFAULT 365, flags INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, public_key TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS reserves(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, original_amount INTEGER NOT NULL, remaining_amount INTEGER NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL, payload TEXT NOT NULL, signature TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, kind TEXT NOT NULL, amount INTEGER NOT NULL, reference TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settlements(token_hash TEXT PRIMARY KEY, token_id TEXT NOT NULL, payer_id TEXT NOT NULL, payee_id TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL, reason TEXT, receipt TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS counters(device_id TEXT NOT NULL, counter INTEGER NOT NULL, nonce TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE, PRIMARY KEY(device_id,counter));
        CREATE TABLE IF NOT EXISTS disputes(id TEXT PRIMARY KEY, settlement_hash TEXT NOT NULL, opened_by TEXT NOT NULL, reason TEXT NOT NULL, evidence TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', decision TEXT, created_at TEXT NOT NULL);
        """)
        seeds = [
          ("alice","alice123","customer",10000,365,0),
          ("bob","bob123","customer",10000,180,0),
          ("merchant","shop123","merchant",0,500,0),
          ("analyst","analyst123","analyst",0,800,0),
        ]
        for row in seeds:
            c.execute("INSERT OR IGNORE INTO users VALUES(?,?,?,?,?,?)", row)
init_db()

class Login(BaseModel):
    username: str
    password: str

class DeviceIn(BaseModel):
    device_id: str
    public_key: str

class ReserveIn(BaseModel):
    amount: int = Field(gt=0, le=1000000)

class CertificateIn(BaseModel):
    device_id: str
    per_payment_limit: int = Field(gt=0, le=100000)
    expiry_minutes: int = Field(default=1440, ge=1, le=10080)

class TokenIn(BaseModel):
    token: dict
    receipt: Optional[dict] = None

class DisputeIn(BaseModel):
    token_hash: str
    reason: str = Field(min_length=3, max_length=500)

class DecisionIn(BaseModel):
    decision: str = Field(min_length=3, max_length=500)

def require_user(x_user: str = Header(...)):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (x_user,)).fetchone()
    if not row: raise HTTPException(401, "Login required")
    return dict(row)

def require_analyst(user=Depends(require_user)):
    if user["role"] != "analyst": raise HTTPException(403, "Analyst role required")
    return user

@app.get("/", response_class=HTMLResponse)
def home():
    with open("static/index.html", encoding="utf-8") as f: return f.read()

@app.get("/api/health")
def health(): return {"status":"ok", "service":"OfflinePay Demo"}

@app.get("/api/public-key")
def public_key():
    pub = BANK.public_key()
    return {"algorithm":"Ed25519", "public_key_pem":public_pem(pub)}

@app.post("/api/login")
def login(data: Login):
    with db() as c:
        u = c.execute("SELECT id,role,balance FROM users WHERE id=? AND password=?", (data.username, data.password)).fetchone()
    if not u: raise HTTPException(401, "Invalid username or password")
    return dict(u)

@app.get("/api/wallet")
def wallet(user=Depends(require_user)):
    with db() as c:
        reserve = c.execute("SELECT COALESCE(SUM(remaining_amount),0) n FROM reserves WHERE user_id=?", (user["id"],)).fetchone()["n"]
        original = c.execute("SELECT COALESCE(SUM(original_amount),0) n FROM reserves WHERE user_id=?", (user["id"],)).fetchone()["n"]
        cert = c.execute("SELECT payload FROM certificates WHERE user_id=? ORDER BY created_at DESC LIMIT 1", (user["id"],)).fetchone()
        ledger = c.execute("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 20", (user["id"],)).fetchall()
    return {"user_id":user["id"],"role":user["role"],"balance":user["balance"],"reserve_remaining":reserve,"reserve_total":original,
            "certificate":json.loads(cert["payload"]) if cert else None,"ledger":[dict(x) for x in ledger]}

@app.post("/api/devices")
def register_device(data: DeviceIn, user=Depends(require_user)):
    try:
        pem = data.public_key.encode()
        serialization.load_pem_public_key(pem)
    except Exception: raise HTTPException(400, "Invalid public key PEM")
    with db() as c:
        c.execute("INSERT OR REPLACE INTO devices VALUES(?,?,?,?)", (data.device_id,user["id"],data.public_key,iso()))
    return {"registered":True,"device_id":data.device_id,"note":"Only the public key is uploaded."}

@app.post("/api/reserve")
def add_reserve(data: ReserveIn, user=Depends(require_user)):
    if user["role"] not in ("customer",): raise HTTPException(403, "Only customers can add reserve")
    with db() as c:
        u = c.execute("SELECT balance FROM users WHERE id=?", (user["id"],)).fetchone()
        if u["balance"] < data.amount: raise HTTPException(400, "Insufficient wallet balance")
        rid = secrets.token_hex(12)
        c.execute("UPDATE users SET balance=balance-? WHERE id=?", (data.amount,user["id"]))
        c.execute("INSERT INTO reserves VALUES(?,?,?,?,?)",(rid,user["id"],data.amount,data.amount,iso()))
        c.execute("INSERT INTO ledger(user_id,kind,amount,reference,created_at) VALUES(?,?,?,?,?)",(user["id"],"reserve_lock",-data.amount,rid,iso()))
    return {"reserve_id":rid,"locked_amount":data.amount}

@app.post("/api/certificates")
def issue_certificate(data: CertificateIn, user=Depends(require_user)):
    if user["role"] != "customer": raise HTTPException(403, "Only customers can receive certificates")
    with db() as c:
        dev = c.execute("SELECT * FROM devices WHERE id=? AND user_id=?", (data.device_id,user["id"])).fetchone()
        reserve = c.execute("SELECT COALESCE(SUM(remaining_amount),0) n FROM reserves WHERE user_id=?", (user["id"],)).fetchone()["n"]
    if not dev: raise HTTPException(400, "Register this device first")
    if reserve <= 0: raise HTTPException(400, "Add funds to offline reserve first")
    tier = "low" if user["account_age_days"] >= 180 and user["flags"] == 0 else ("medium" if user["account_age_days"] >= 30 else "high")
    tier_limit = {"low":5000,"medium":2000,"high":500}
    limit = min(data.per_payment_limit, tier_limit[tier], reserve)
    reason = {"low":"Established account with no flags.","medium":"Standard limit due to account history.","high":"Reduced limit for newer or flagged accounts."}[tier]
    payload = {"certificate_id":secrets.token_hex(16),"device_id":data.device_id,"user_id":user["id"],
      "reserve_amount":reserve,"per_payment_limit":limit,"risk_tier":tier,"risk_reason":reason,
      "issued_at":iso(),"expires_at":iso(now()+timedelta(minutes=data.expiry_minutes)),"algorithm":"Ed25519"}
    sig = b64(BANK.sign(canonical(payload)))
    with db() as c:
        c.execute("INSERT INTO certificates VALUES(?,?,?,?,?,?)",(payload["certificate_id"],user["id"],data.device_id,json.dumps(payload),sig,iso()))
    return {"payload":payload,"signature":sig,"bank_public_key_pem":public_pem(BANK.public_key())}

@app.post("/api/sync")
def sync(data: TokenIn, user=Depends(require_user)):
    token = data.token
    required = ["token_id","certificate","certificate_signature","device_public_key","payee_id","amount","nonce","counter","created_at","expires_at","signature"]
    if any(k not in token for k in required): raise HTTPException(400, "Token missing required fields")
    token_body = {k:token[k] for k in required if k != "signature"}
    token_hash = hashlib.sha256(canonical(token)).hexdigest()
    with db() as c:
        prior = c.execute("SELECT * FROM settlements WHERE token_hash=?", (token_hash,)).fetchone()
        if prior: return {"status":prior["status"],"idempotent":True,"reason":prior["reason"],"token_hash":token_hash}
        cert = token["certificate"]
        cert_id = cert.get("certificate_id")
        cert_row = c.execute("SELECT * FROM certificates WHERE id=?", (cert_id,)).fetchone()
        if not cert_row:
            return record_flag(c,token_hash,token,"rejected","Unknown certificate")
        try:
            BANK.public_key().verify(unb64(token["certificate_signature"]),canonical(cert))
            device_key = serialization.load_pem_public_key(token["device_public_key"].encode())
            device_key.verify(unb64(token["signature"]),canonical(token_body))
        except Exception:
            return record_flag(c,token_hash,token,"rejected","Invalid certificate or token signature")
        if cert.get("user_id") != token.get("payer_id"):
            return record_flag(c,token_hash,token,"rejected","Payer does not match certificate")
        if cert.get("device_id") != token.get("device_id"):
            return record_flag(c,token_hash,token,"rejected","Device does not match certificate")
        if cert.get("expires_at","") < iso():
            return record_flag(c,token_hash,token,"rejected","Certificate expired")
        if token["expires_at"] < iso():
            return record_flag(c,token_hash,token,"rejected","Token expired")
        try: amount = int(token["amount"]); counter = int(token["counter"])
        except Exception: return record_flag(c,token_hash,token,"rejected","Invalid amount or counter")
        if amount <= 0 or amount > int(cert["per_payment_limit"]):
            return record_flag(c,token_hash,token,"flagged","Payment exceeds per-payment limit")
        dev = c.execute("SELECT * FROM devices WHERE id=? AND user_id=?", (token["device_id"],token["payer_id"])).fetchone()
        if not dev or dev["public_key"].strip() != token["device_public_key"].strip():
            return record_flag(c,token_hash,token,"rejected","Device key not registered")
        existing = c.execute("SELECT * FROM counters WHERE device_id=? AND counter=?", (token["device_id"],counter)).fetchone()
        nonce = c.execute("SELECT * FROM counters WHERE nonce=?", (token["nonce"],)).fetchone()
        if existing or nonce:
            return record_flag(c,token_hash,token,"flagged","Counter or nonce reused (possible replay/double spend)")
        reserve = c.execute("SELECT * FROM reserves WHERE user_id=? AND remaining_amount>0 ORDER BY created_at LIMIT 1", (token["payer_id"],)).fetchone()
        if not reserve or reserve["remaining_amount"] < amount:
            return record_flag(c,token_hash,token,"flagged","Overspend: reserve is insufficient; loss remains bounded by reserve")
        payee = c.execute("SELECT * FROM users WHERE id=? AND role IN ('merchant','customer')", (token["payee_id"],)).fetchone()
        if not payee: return record_flag(c,token_hash,token,"rejected","Unknown payee")
        c.execute("UPDATE reserves SET remaining_amount=remaining_amount-? WHERE id=?", (amount,reserve["id"]))
        c.execute("UPDATE users SET balance=balance+? WHERE id=?", (amount,token["payee_id"]))
        c.execute("INSERT INTO ledger(user_id,kind,amount,reference,created_at) VALUES(?,?,?,?,?)",(token["payer_id"],"offline_settlement",-amount,token_hash,iso()))
        c.execute("INSERT INTO ledger(user_id,kind,amount,reference,created_at) VALUES(?,?,?,?,?)",(token["payee_id"],"offline_payment_received",amount,token_hash,iso()))
        c.execute("INSERT INTO counters VALUES(?,?,?,?)",(token["device_id"],counter,token["nonce"],token_hash))
        receipt_body={"receipt_id":secrets.token_hex(12),"token_hash":token_hash,"payer_id":token["payer_id"],"payee_id":token["payee_id"],"amount":amount,"settled_at":iso(),"status":"settled"}
        receipt={"payload":receipt_body,"signature":b64(BANK.sign(canonical(receipt_body)))}
        c.execute("INSERT INTO settlements VALUES(?,?,?,?,?,?,?,?,?)",(token_hash,token["token_id"],token["payer_id"],token["payee_id"],amount,"settled",None,json.dumps(receipt),iso()))
        return {"status":"settled","idempotent":False,"token_hash":token_hash,"receipt":receipt}

def record_flag(c, token_hash, token, status, reason):
    payer = str(token.get("payer_id","unknown"))
    payee = str(token.get("payee_id","unknown"))
    try: amount = int(token.get("amount",0))
    except Exception: amount = 0
    c.execute("INSERT OR IGNORE INTO settlements VALUES(?,?,?,?,?,?,?,?,?)",(token_hash,str(token.get("token_id","unknown")),payer,payee,amount,status,reason,None,iso()))
    if status == "flagged":
        c.execute("UPDATE users SET flags=flags+1 WHERE id=?", (payer,))
    return {"status":status,"idempotent":False,"reason":reason,"token_hash":token_hash}

@app.get("/api/transactions")
def transactions(user=Depends(require_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM settlements WHERE payer_id=? OR payee_id=? ORDER BY created_at DESC LIMIT 100",(user["id"],user["id"])).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/disputes")
def open_dispute(data: DisputeIn, user=Depends(require_user)):
    with db() as c:
        s = c.execute("SELECT * FROM settlements WHERE token_hash=?", (data.token_hash,)).fetchone()
        if not s: raise HTTPException(404,"Transaction not found")
        if user["id"] not in (s["payer_id"],s["payee_id"]): raise HTTPException(403,"Only transaction participants can dispute")
        evidence={"settlement":dict(s),"opened_at":iso(),"note":"Submitted token/receipt should be retained by both devices; server stores the settlement record."}
        did=secrets.token_hex(12)
        c.execute("INSERT INTO disputes(id,settlement_hash,opened_by,reason,evidence,status,created_at) VALUES(?,?,?,?,?,'open',?)",(did,data.token_hash,user["id"],data.reason,json.dumps(evidence),iso()))
    return {"dispute_id":did,"status":"open","evidence":evidence}

@app.get("/api/analyst/flags")
def analyst_flags(user=Depends(require_analyst)):
    with db() as c:
        rows=c.execute("SELECT * FROM settlements WHERE status IN ('flagged','rejected') ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/analyst/disputes")
def analyst_disputes(user=Depends(require_analyst)):
    with db() as c: rows=c.execute("SELECT * FROM disputes ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/analyst/disputes/{dispute_id}/decision")
def decide_dispute(dispute_id: str, data: DecisionIn, user=Depends(require_analyst)):
    with db() as c:
        cur=c.execute("UPDATE disputes SET status='decided',decision=? WHERE id=? AND status='open'",(data.decision,dispute_id))
        if cur.rowcount == 0: raise HTTPException(404,"Open dispute not found")
    return {"dispute_id":dispute_id,"status":"decided","decision":data.decision}

@app.post("/api/reset-demo")
def reset_demo():
    # Demo-only convenience. Do not expose this endpoint in production.
    if os.getenv("ALLOW_DEMO_RESET","1") != "1": raise HTTPException(403,"Reset disabled")
    with db() as c:
        for table in ("devices","reserves","certificates","ledger","settlements","counters","disputes"):
            c.execute(f"DELETE FROM {table}")
        c.execute("UPDATE users SET balance=CASE id WHEN 'alice' THEN 10000 WHEN 'bob' THEN 10000 ELSE 0 END, flags=0")
    return {"reset":True}

app.mount("/static", StaticFiles(directory="static"), name="static")
