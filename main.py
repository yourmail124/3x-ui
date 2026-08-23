import asyncio
import json
import os
import hashlib
import secrets
import time
import aiofiles
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends, UploadFile, File
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Gateway")

IRAN_TZ = ZoneInfo("Asia/Tehran")
app = FastAPI(title="Gateway", docs_url=None, redoc_url=None)

# ── Persistence ───────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "app_state.json"
SECRET_FILE = DATA_DIR / "app_secret.key"
SAVE_LOCK = asyncio.Lock()

def _load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret: return env_secret
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if SECRET_FILE.exists():
            return SECRET_FILE.read_text(encoding="utf-8").strip()
        new_secret = secrets.token_urlsafe(32)
        SECRET_FILE.write_text(new_secret, encoding="utf-8")
        return new_secret
    except Exception: return secrets.token_urlsafe(32)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": _load_or_create_secret(),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

async def load_state():
    global LINKS, AUTH, SUBS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.loads(await f.read())
            LINKS.update(data.get("links", {}))
            SUBS.update(data.get("subs", {}))
            if "password_hash" in data: AUTH["password_hash"] = data["password_hash"]
    except Exception: pass

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {"links": dict(LINKS), "subs": dict(SUBS), "password_hash": AUTH["password_hash"], "saved_at": datetime.now().isoformat()}
            async with aiofiles.open(DATA_FILE, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
        except Exception: pass

# ── In-memory state ───────────────────────────────────────────────────────────
connections: dict = {}
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs, activity_logs = deque(maxlen=50), deque(maxlen=200)
hourly_traffic, http_client = defaultdict(int), None
LINKS, LINKS_LOCK = {}, asyncio.Lock()
SUBS, SUBS_LOCK = {}, asyncio.Lock()

PROTOCOLS = ("vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one")
DEFAULT_PROTOCOL = "vless-ws"
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
DEFAULT_FINGERPRINT = "chrome"
DEFAULT_ALPN_BY_PROTOCOL = {"vless-ws": "http/1.1", "xhttp-packet-up": "h2,http/1.1", "xhttp-stream-up": "h2,http/1.1", "xhttp-stream-one": "h2,http/1.1"}
DEFAULT_PORT = 443
MIN_PORT, MAX_PORT = 1, 65535

def log_activity(kind, message, level="info"):
    activity_logs.append({"kind": kind, "level": level, "message": message, "time": datetime.now().isoformat()})

# ── Auth & Sessions ───────────────────────────────────────────────────────────
SESSION_COOKIE = "app_session"
SESSION_TTL = 60 * 60 * 24 * 365
def hash_password(pw): return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()
AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "ADMIN123"))}
SESSIONS, SESSIONS_LOCK = {}, asyncio.Lock()

async def create_session():
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK: SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token):
    if not token: return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        return exp is not None and exp > time.time()

async def require_auth(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)): raise HTTPException(status_code=401)
    return True

# ── System API (Backup & Restore) ─────────────────────────────────────────────
@app.get("/api/system/backup")
async def download_backup(_=Depends(require_auth)):
    async with LINKS_LOCK:
        async with SUBS_LOCK:
            data = {"links": dict(LINKS), "subs": dict(SUBS), "password_hash": AUTH["password_hash"], "backup_time": datetime.now().isoformat()}
    return JSONResponse(content=data, headers={"Content-Disposition": f"attachment; filename=backup_{int(time.time())}.json"})

@app.post("/api/system/restore")
async def upload_restore(file: UploadFile = File(...), _=Depends(require_auth)):
    try:
        data = json.loads(await file.read())
        if "links" not in data or "subs" not in data: raise ValueError("Invalid File")
        async with LINKS_LOCK:
            async with SUBS_LOCK:
                LINKS.clear(); LINKS.update(data["links"])
                SUBS.clear(); SUBS.update(data["subs"])
                if "password_hash" in data: AUTH["password_hash"] = data["password_hash"]
        await save_state()
        log_activity("system", "بازگردانی دیتابیس انجام شد", "warn")
        return {"ok": True}
    except Exception as e: raise HTTPException(status_code=400, detail=str(e))

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_host(request=None):
    if request:
        h = request.headers.get("x-forwarded-host") or request.headers.get("host")
        if h: CONFIG["host"] = h.split(":")[0]
    return CONFIG["host"]

def generate_uuid(): return str(secrets.token_urlsafe(16)).replace('_','-').replace('-','')[:32]
def now_ir(): return datetime.now(IRAN_TZ)
def uptime(): return str(timedelta(seconds=int(time.time() - stats["start_time"])))
def fmt_bytes(b):
    for unit in ['B','KB','MB','GB','TB']:
        if b < 1024: return f"{b:.1f} {unit}"
        b /= 1024
def parse_size_to_bytes(v, u):
    mult = {"GB": 1024**3, "MB": 1024**2, "KB": 1024}
    return int(v * mult.get(u.upper(), 1))

def is_link_allowed(link):
    if not link or not link.get("active", True): return False
    if link.get("expires_at") and datetime.now() > datetime.fromisoformat(link["expires_at"]): return False
    if link.get("limit_bytes", 0) > 0 and link["used_bytes"] >= link["limit_bytes"]: return False
    return True

def generate_vless_link(uuid, host, remark, protocol, fp, alpn, port):
    fp = fp or "chrome"
    alpn = alpn or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")
    p_val = port or 443
    path = f"/{'ws' if 'ws' in protocol else 'xhttp-siz10'}/{protocol.replace('xhttp-','') if 'xhttp' in protocol else ''}/{uuid}".replace('//','/')
    tp = "ws" if "ws" in protocol else "xhttp"
    query = f"encryption=none&security=tls&type={tp}&host={host}&path={quote(path)}&sni={host}&fp={fp}&alpn={quote(alpn)}"
    if tp == "xhttp": query += f"&mode={protocol.replace('xhttp-','')}"
    return f"vless://{uuid}@{host}:{p_val}?{query}#{quote(remark)}"

def vless_link_for_link(link, uid, host):
    return generate_vless_link(uid, host, f"User-{link['label']}", link['protocol'], link['fingerprint'], link['alpn'], link['port'])

# ── API Link Management ───────────────────────────────────────────────────────
@app.post("/api/links")
async def api_create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": body.get("label", "NewUser"),
            "limit_bytes": parse_size_to_bytes(float(body.get("limit_value", 0)), body.get("limit_unit", "GB")),
            "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True,
            "expires_at": (datetime.now() + timedelta(days=int(body.get("expires_days", 0)))).isoformat() if int(body.get("expires_days", 0)) > 0 else None,
            "protocol": body.get("protocol", DEFAULT_PROTOCOL), "fingerprint": body.get("fingerprint", DEFAULT_FINGERPRINT),
            "alpn": body.get("alpn", ""), "port": int(body.get("port", 443)), "ip_limit": int(body.get("ip_limit", 0))
        }
    await save_state()
    return {"ok": True, "uuid": uid}

@app.get("/api/links")
async def api_list_links(request: Request, _=Depends(require_auth)):
    h = get_host(request)
    return {"links": [{"uuid": k, **v, "vless": vless_link_for_link(v, k, h)} for k, v in LINKS.items()]}

@app.delete("/api/links/{uid}")
async def api_delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK: LINKS.pop(uid, None)
    await save_state()
    return {"ok": True}

@app.get("/stats")
async def api_stats(_=Depends(require_auth)):
    return {"uptime": uptime(), "total_traffic": fmt_bytes(stats["total_bytes"]), "active_conns": len(connections)}

# ── Routes & HTML ─────────────────────────────────────────────────────────────
from pages import LOGIN_HTML, DASHBOARD_HTML, get_public_page_html

@app.get("/login", response_class=HTMLResponse)
async def login_page(): return LOGIN_HTML

@app.post("/api/login")
async def api_login(request: Request):
    b = await request.json()
    if hash_password(b.get("password", "")) != AUTH["password_hash"]: raise HTTPException(status_code=401)
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, max_age=SESSION_TTL)
    return resp

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)): return RedirectResponse("/login")
    return DASHBOARD_HTML

@app.get("/p/{key}", response_class=HTMLResponse)
async def public_page(key: str): return get_public_page_html(key)

from relay_vless import websocket_tunnel
app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])