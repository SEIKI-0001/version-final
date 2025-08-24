# ===== Standard library =====
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

# ===== Third-party =====
import pandas as pd
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials as UserCredentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.cloud import storage

# ====== 環境変数 ======
USER_TZ = os.getenv("USER_TZ", "Asia/Tokyo")
TZ_OFFSET = os.getenv("TZ_OFFSET", "+09:00")
BASE_URL = os.getenv("BASE_URL")  # 例: https://version-final-xxxx.a.run.app
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
APP_SECRET = os.getenv("APP_SECRET", "")
TOKEN_BUCKET = os.getenv("TOKEN_BUCKET", "gpts-oauth-tokens")
USER_SHEET_MAP_BUCKET = os.getenv("USER_SHEET_MAP_BUCKET", "user-sheet-mapping")
USER_SHEET_MAP_BLOB = os.getenv("USER_SHEET_MAP_BLOB", "mapping.json")
BACKUP_BUCKET = os.getenv("BACKUP_BUCKET", "gpts-plans-backup")  


# Google API スコープ（必要最低限：Sheets/Drive.file/Calendar.events）
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/calendar.events",
]

# ====== FastAPI ======
app = FastAPI()

# ====== ヘルスチェック ======
def required_envs_ok() -> bool:
    return all([BASE_URL, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, APP_SECRET, TOKEN_BUCKET])

@app.get("/")
def root():
    return {"ok": True}

@app.get("/health")
def health():
    return {"ok": True, "env_ready": required_envs_ok()}

# ====== GCS トークン保存 ======
def _token_bucket() -> storage.Bucket:
    client = storage.Client()
    return client.bucket(TOKEN_BUCKET)

def _token_blob_path(user_id: str) -> str:
    safe = base64.urlsafe_b64encode(user_id.encode()).decode().rstrip("=")
    return f"tokens/{safe}.json"

def save_refresh_token(user_id: str, refresh_token: str):
    bucket = _token_bucket()
    blob = bucket.blob(_token_blob_path(user_id))
    data = {"user_id": user_id, "refresh_token": refresh_token, "updated_at": int(time.time())}
    blob.upload_from_string(json.dumps(data), content_type="application/json")

def load_refresh_token(user_id: str) -> Optional[str]:
    bucket = _token_bucket()
    blob = bucket.blob(_token_blob_path(user_id))
    if not blob.exists():
        return None
    data = json.loads(blob.download_as_text())
    return data.get("refresh_token")

# ====== OAuth Flow ======
def oauth_redirect_uri() -> str:
    # 例: https://<cloud-run>/oauth/callback
    base = (BASE_URL or "").rstrip("/")
    return f"{base}/oauth/callback"

def build_flow() -> Flow:
    client_config = {
        "web": {
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [oauth_redirect_uri()],
        }
    }
    return Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=oauth_redirect_uri(),
    )

# state 署名（改ざん防止 & TTL）
STATE_TTL = 10 * 60  # 10分

def signed_state(user_id: str) -> str:
    ts = int(time.time())
    msg = f"{user_id}|{ts}".encode()
    sig = hmac.new(APP_SECRET.encode(), msg, hashlib.sha256).digest()
    packed = base64.urlsafe_b64encode(msg + b"|" + base64.urlsafe_b64encode(sig)).decode()
    return packed.rstrip("=")

def verify_state(state: str) -> Optional[str]:
    try:
        raw = base64.urlsafe_b64decode(state + "===")
        parts = raw.split(b"|")
        if len(parts) == 3:
            user_id = parts[0].decode()
            ts = int(parts[1].decode())
            sig_b64 = parts[2]
            expected = hmac.new(APP_SECRET.encode(), f"{user_id}|{ts}".encode(), hashlib.sha256).digest()
            if hmac.compare_digest(base64.urlsafe_b64encode(expected), sig_b64):
                if time.time() - ts <= STATE_TTL:
                    return user_id
            return None
        return None
    except Exception:
        return None

# 認可開始
@app.get("/oauth/start")
def oauth_start(user_id: Optional[str] = None):
    if not required_envs_ok():
        return JSONResponse({"error": "OAuth env not set"}, status_code=500)
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    flow = build_flow()
    state = signed_state(user_id)
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        state=state,
    )
    return RedirectResponse(auth_url, status_code=302)

# コールバック
@app.get("/oauth/callback")
def oauth_callback(request: Request):
    if not required_envs_ok():
        return HTMLResponse("<h3>OAuth env not set</h3>", status_code=500)

    state = request.query_params.get("state", "")
    user_id = verify_state(state) or ""
    if not user_id:
        return HTMLResponse("<h3>Invalid state</h3>", status_code=400)

    code = request.query_params.get("code")
    if not code:
        return HTMLResponse("<h3>Missing code</h3>", status_code=400)

    try:
        flow = build_flow()
        flow.fetch_token(code=code)
        creds = flow.credentials
        rt = getattr(creds, "refresh_token", None)
        if not rt:
            # Google 側の仕様で返らないことがある → 既存の保存があればOK
            existing = load_refresh_token(user_id)
            if not existing:
                return HTMLResponse("<h3>⚠️ refresh_token が取得できませんでした。もう一度お試しください。</h3>", status_code=400)
            return HTMLResponse("<h3>✅ 連携済みです。チャットに戻って再実行してください。</h3>")
        save_refresh_token(user_id, rt)
        return HTMLResponse("<h3>✅ 連携が完了しました。チャットに戻って再実行してください。</h3>")
    except Exception as e:
        return HTMLResponse(f"<h3>OAuth error: {e}</h3>", status_code=400)

# 簡易ステータス確認
@app.get("/auth/status")
def auth_status(user_id: Optional[str] = None):
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)
    has = bool(load_refresh_token(user_id))
    return {"user_id": user_id, "authorized": has}

#OAuth refresh_token → Credentials 再構築ヘルパー
def load_user_credentials(user_id: str) -> Optional[UserCredentials]:
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

def get_user_sheets_service(user_id: str):
    creds = load_user_credentials(user_id)
    if not creds:
        return None
    return build("sheets", "v4", credentials=creds, cache_discovery=False)



#studyplanner置き換え対象
def expand_chapter_items(counts: List[int]) -> List[str]:
    items = []
    for idx, c in enumerate(counts):
        for j in range(1, c + 1):
            items.append(f"Chapter {idx+1} - Item {j}")
    return items

def load_chapter_data_from_gcs(book_filename: str) -> List[str]:
    # study-book-data/<book>.json に ["Chapter 1 - Item 1", ...] 形式で置く想定
    client = storage.Client()
    bucket = client.bucket("study-book-data")
    blob = bucket.blob(book_filename)
    return json.loads(blob.download_as_text())

DAY_ABBR = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

@dataclass
class UserSetting:
    user_id: str
    target_exam: datetime
    start_date: datetime
    weekday_minutes: int
    weekend_minutes: int
    rest_days: List[str]
    weekday_start: str
    weekend_start: str
    book_keyword: str

def _weekday_minutes(user: UserSetting, d: datetime) -> int:
    if DAY_ABBR[d.weekday()] in set(user.rest_days):
        return 0
    return user.weekend_minutes if d.weekday() >= 5 else user.weekday_minutes

def generate_study_plan(payload: dict, user_id: str) -> Tuple[pd.DataFrame, UserSetting]:
    user = UserSetting(
        user_id=user_id,
        target_exam=datetime.strptime(payload["target_exam_date"], "%Y-%m-%d"),
        start_date=datetime.strptime(payload["start_date"], "%Y-%m-%d"),
        weekday_minutes=int(payload["weekday_minutes"]),
        weekend_minutes=int(payload["weekend_minutes"]),
        rest_days=payload.get("rest_days", ["Wed"]),
        weekday_start=payload.get("weekday_start", "20:00"),
        weekend_start=payload.get("weekend_start", "13:00"),
        book_keyword=payload["book_keyword"],
    )

    # 章リスト（counts or 文字列リスト）
    chapter_items_list = payload.get("chapter_items_list")
    if chapter_items_list:
        if all(isinstance(x, int) for x in chapter_items_list):
            chapter_items_list = expand_chapter_items(chapter_items_list)
    else:
        chapter_items_list = load_chapter_data_from_gcs(f"{user.book_keyword}.json")

    # —— 簡易割当: 初回周回を MIN=10分単位で順番に詰める
    MIN = 10
    d = user.start_date
    tasks = []
    i = 0
    while i < len(chapter_items_list) and d <= user.target_exam:
        avail = _weekday_minutes(user, d)
        if avail == 0:
            d += timedelta(days=1); continue
        used = 0
        start_of_day = True
        while i < len(chapter_items_list) and used + MIN <= avail:
            name = chapter_items_list[i]
            tasks.append({
                "WBS": "",  # 後で連番
                "Task Name": name,
                "Date": d.strftime("%Y-%m-%d"),
                "Day": DAY_ABBR[d.weekday()],
                "Duration": MIN,
                "Status": "未着手",
            })
            used += MIN
            i += 1
            start_of_day = False
        d += timedelta(days=1)

    # DataFrame 化 & WBS 採番
    df = pd.DataFrame(tasks, columns=["WBS", "Task Name", "Date", "Day", "Duration", "Status"])
    df["WBS"] = [f"wbs{i}" for i in range(len(df))]
    return df, user

#シート作成＆書き込み、マッピング保存
def create_sheet_and_write(plan_df: pd.DataFrame, sheet_title: str, user_id: str) -> str:
    svc = get_user_sheets_service(user_id)
    if svc is None:
        raise PermissionError("No OAuth tokens. Authorize first.")

    sheet = svc.spreadsheets().create(
        body={"properties": {"title": sheet_title}}, fields="spreadsheetId"
    ).execute()
    spreadsheet_id = sheet["spreadsheetId"]

    svc.spreadsheets().values().update(
        spreadsheetId=spreadsheet_id, range="A1", valueInputOption="RAW",
        body={"values": [list(plan_df.columns)]}
    ).execute()
    if not plan_df.empty:
        svc.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id, range="A2", valueInputOption="RAW",
            body={"values": plan_df.values.tolist()}
        ).execute()
    return spreadsheet_id

def generate_sheet_title(user: UserSetting) -> str:
    return f"user_{user.user_id}_plan_{user.start_date.strftime('%Y%m%d')}"

def load_user_sheet_map() -> Dict[str, Dict[str, str]]:
    client = storage.Client()
    bucket = client.bucket(USER_SHEET_MAP_BUCKET)
    blob = bucket.blob(USER_SHEET_MAP_BLOB)
    if not blob.exists():
        return {}
    return json.loads(blob.download_as_text())

def save_user_sheet_map(mapping: Dict[str, Dict[str, str]]) -> None:
    client = storage.Client()
    bucket = client.bucket(USER_SHEET_MAP_BUCKET)
    blob = bucket.blob(USER_SHEET_MAP_BLOB)
    blob.upload_from_string(json.dumps(mapping, ensure_ascii=False), content_type="application/json")


#/generate エンドポイント（FastAPI版）
from fastapi import Body

@app.post("/generate")
def generate_plan(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    # 認可チェック（未連携なら authorize_url を 200 で返す）
    if not load_user_credentials(user_id):
        if not required_envs_ok():
            return JSONResponse({"error": "OAuth not configured on server"}, status_code=500)
        flow = build_flow()
        auth_url, _ = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent",
            state=signed_state(user_id)
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Please authorize via the URL, then retry."
        }, status_code=200)

    # 生成 → Sheets 書き込み
    try:
        plan_df, user = generate_study_plan(payload, user_id)
    except Exception as e:
        return JSONResponse({"error": f"plan generation failed: {e}"}, status_code=400)

    try:
        spreadsheet_id = create_sheet_and_write(plan_df, generate_sheet_title(user), user_id)
    except PermissionError:
        flow = build_flow()
        auth_url, _ = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent",
            state=signed_state(user_id)
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Authorization expired. Please re-authorize."
        }, status_code=200)
    except Exception as e:
        return JSONResponse({"error": f"Sheets error: {e}"}, status_code=500)

    spreadsheet_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}"

    # マッピング保存（任意：失敗しても処理は続行）
    try:
        mapping = load_user_sheet_map()
        mapping[user_id] = {"spreadsheet_id": spreadsheet_id, "spreadsheet_url": spreadsheet_url}
        save_user_sheet_map(mapping)
    except Exception as e:
        print("[warn] save mapping failed:", e)

    return {
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": spreadsheet_url,
        "plan_rows": len(plan_df)
        # 必要なら "plan": plan_df.to_dict(orient="records") を返す
    }

