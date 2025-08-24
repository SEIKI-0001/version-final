import os, json, time, base64, hmac, hashlib
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from google.cloud import storage
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials as UserCredentials
from google.auth.transport.requests import Request as GoogleRequest

app = FastAPI()

# ====== Config ======
USER_TZ = os.getenv("USER_TZ", "Asia/Tokyo")
TZ_OFFSET = os.getenv("TZ_OFFSET", "+09:00")
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "")
OAUTH_REDIRECT_PATH = os.getenv("OAUTH_REDIRECT_PATH", "/oauth/callback")
BASE_URL = os.getenv("BASE_URL", "")  # 未設定でも動くよう動的生成にフォールバック
APP_SECRET = os.getenv("APP_SECRET", "")  # ランダム文字列を設定必須
TOKEN_BUCKET = os.getenv("TOKEN_BUCKET", "gpts-oauth-tokens")

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/calendar.events",
]

# ====== Helpers ======
def required_envs_ok() -> bool:
    return all([OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, APP_SECRET])

def oauth_redirect_uri(request: Request) -> str:
    if BASE_URL:
        return f"{BASE_URL.rstrip('/')}{OAUTH_REDIRECT_PATH}"
    # Cloud Run の実URLから動的生成（BASE_URL未設定でもOK）
    return str(request.url_for("oauth_callback"))

STATE_TTL = 10 * 60  # 10分

def signed_state(user_id: str) -> str:
    ts = int(time.time())
    msg = f"{user_id}|{ts}".encode()
    sig = hmac.new(APP_SECRET.encode(), msg, hashlib.sha256).digest()
    packed = base64.urlsafe_b64encode(msg + b"|" + base64.urlsafe_b64encode(sig)).decode()
    return packed.rstrip("=")

def verify_state(state: str) -> str | None:
    try:
        raw = base64.urlsafe_b64decode(state + "===")
        parts = raw.split(b"|")
        if len(parts) == 3:
            user_id = parts[0].decode()
            ts = int(parts[1].decode())
            sig_b64 = parts[2]
            expected = hmac.new(APP_SECRET.encode(), f"{user_id}|{ts}".encode(), hashlib.sha256).digest()
            if hmac.compare_digest(base64.urlsafe_b64encode(expected), sig_b64) and (time.time() - ts <= STATE_TTL):
                return user_id
        return None
    except Exception:
        return None

def build_flow(redirect_uri: str) -> Flow:
    client_config = {
        "web": {
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }
    return Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=redirect_uri)

def token_bucket() -> storage.Bucket:
    client = storage.Client()
    return client.bucket(TOKEN_BUCKET)

def token_blob_path(user_id: str) -> str:
    safe = base64.urlsafe_b64encode(user_id.encode()).decode().rstrip("=")
    return f"tokens/{safe}.json"

def save_refresh_token(user_id: str, refresh_token: str):
    bucket = token_bucket()
    blob = bucket.blob(token_blob_path(user_id))
    data = {"user_id": user_id, "refresh_token": refresh_token, "updated_at": int(time.time())}
    blob.upload_from_string(json.dumps(data), content_type="application/json")

def load_refresh_token(user_id: str) -> str | None:
    bucket = token_bucket()
    blob = bucket.blob(token_blob_path(user_id))
    if not blob.exists():
        return None
    try:
        data = json.loads(blob.download_as_text())
        return data.get("refresh_token")
    except Exception:
        return None

def load_user_credentials(user_id: str) -> UserCredentials | None:
    rt = load_refresh_token(user_id)
    if not rt:
        return None
    creds = UserCredentials(
        token=None,
        refresh_token=rt,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=OAUTH_CLIENT_ID,
        client_secret=OAUTH_CLIENT_SECRET,
        scopes=SCOPES,
    )
    try:
        if not creds.valid:
            creds.refresh(GoogleRequest())
    except Exception:
        return None
    return creds

# ====== Health & Root ======
@app.get("/")
def root():
    return {"message": "Hello, World! from FastAPI"}

@app.get("/healthz")
def healthz():
    return {"ok": True, "env_ready": required_envs_ok()}

# ====== OAuth endpoints ======
@app.get("/oauth/start")
def oauth_start(user_id: str, request: Request):
    if not required_envs_ok():
        raise HTTPException(status_code=500, detail="OAuth env not set (CLIENT_ID/SECRET/APP_SECRET)")
    redirect_uri = oauth_redirect_uri(request)
    flow = build_flow(redirect_uri)
    state = signed_state(user_id)
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        state=state,
    )
    return RedirectResponse(auth_url)

@app.get("/oauth/callback", name="oauth_callback")
def oauth_callback(request: Request, state: str = "", code: str = ""):
    if not required_envs_ok():
        return HTMLResponse("<h3>OAuth env not set</h3>", status_code=500)
    user_id = verify_state(state) or ""
    if not user_id:
        return HTMLResponse("<h3>Invalid state</h3>", status_code=400)
    redirect_uri = oauth_redirect_uri(request)
    flow = build_flow(redirect_uri)
    if not code:
        return HTMLResponse("<h3>Missing code</h3>", status_code=400)
    flow.fetch_token(code=code)
    creds = flow.credentials
    rt = getattr(creds, "refresh_token", None)
    if not rt:
        existing = load_refresh_token(user_id)
        if not existing:
            return HTMLResponse("<h3>⚠️ refresh_tokenが取得できませんでした。もう一度お試しください。</h3>", status_code=400)
        return HTMLResponse("<h3>✅ 連携済みです。チャットに戻って再実行してください。</h3>")
    save_refresh_token(user_id, rt)
    return HTMLResponse("<h3>✅ 連携が完了しました。チャットに戻って再実行してください。</h3>")

# ====== Minimal /generate (まだSheet書込なし) ======
@app.post("/generate")
async def generate(request: Request):
    body = await request.json()
    user_id = (body or {}).get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")
    creds = load_user_credentials(user_id)
    if not creds:
        # 認可URLを返す（200）→ フロント側はこのURLへ誘導
        redirect_uri = oauth_redirect_uri(request)
        flow = build_flow(redirect_uri)
        auth_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            state=signed_state(user_id),
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Please authorize via the URL, then retry the command."
        })
    # ここから先は「認証済み」→ 後でSheets/Calendar処理を実装
    return {"requires_auth": False, "message": "Authorized. Ready for plan generation."}

port = int(os.environ.get("PORT", "8080"))
app.run(host="0.0.0.0", port=port)
