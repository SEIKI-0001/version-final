# ===== Standard Library =====
import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional, List, Tuple, Dict

# ===== Third-party =====
import pandas as pd
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials as UserCredentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.cloud import storage
import random
from pydantic import BaseModel, AnyUrl
from fastapi.openapi.utils import get_openapi
from google.auth.exceptions import RefreshError

# ===== Configuration (env) =====
USER_TZ = os.getenv("USER_TZ", "Asia/Tokyo")         # 予約（将来のタイムゾーン対応）
TZ_OFFSET = os.getenv("TZ_OFFSET", "+09:00")         # 予約（将来のタイムゾーン対応）
BASE_URL = os.getenv("BASE_URL")                     # 例: https://your-service-xxxx.a.run.app
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
APP_SECRET = os.getenv("APP_SECRET", "")
TOKEN_BUCKET = os.getenv("TOKEN_BUCKET", "gpts-oauth-tokens")
USER_SHEET_MAP_BUCKET = os.getenv("USER_SHEET_MAP_BUCKET", "user-sheet-mapping")
USER_SHEET_MAP_BLOB = os.getenv("USER_SHEET_MAP_BLOB", "mapping.json")
BACKUP_BUCKET = os.getenv("BACKUP_BUCKET", "gpts-plans-backup")
SERVICE_API_KEY = os.getenv("SERVICE_API_KEY", "")
BOOK_DATA_BUCKET = os.getenv("BOOK_DATA_BUCKET", "study-book-data")

ACRONYM_BUCKET = os.getenv("ACRONYM_BUCKET", "maru-acronyms")
ACRONYM_PATH = os.getenv("ACRONYM_PATH", "acronyms/itpass_core.json")
ACRONYM_REFRESH_SEC = int(os.getenv("ACRONYM_REFRESH_SEC", "3600"))

_AC_CACHE = {"terms": {}, "last": 0, "etag": None}

# スコープ（当面 Calendar 未使用ならコメントアウト可）
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/calendar.events",  # ← 未使用なら外してもOK
]

# ===== フィールド→列マッピング（列名はヘッダに合わせる） =====
FIELD_TO_COL = {
    "task name": "B",
    "date": "C",
    "day": "D",
    "duration": "E",
    "status": "F",
}

# ===== その他の定数 =====
EXEMPT_PATHS = {"/", "/health", "/oauth/start", "/oauth/callback", "/auth/status"}
STATE_TTL = 10 * 60  # OAuth state TTL (seconds)
def _state_blob(state: str):
    return _token_bucket().blob(f"oauth_state/{state}.json")
    
def save_oauth_state(state: str, data: dict):
    data = {**data, "exp": int(time.time()) + STATE_TTL}
    _state_blob(state).upload_from_string(json.dumps(data), content_type="application/json")

def pop_oauth_state(state: str) -> Optional[dict]:
    b = _state_blob(state)
    try:
        data = json.loads(b.download_as_text())
        if data.get("exp", 0) < int(time.time()):
            return None
        try:
            b.delete()
        except Exception:
            pass
        return data
    except Exception:
        return None
        
DAY_ABBR = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

# ===== FastAPI =====
app = FastAPI()

_GCS = None
_SHEETS = {}        # {user_id: sheets_service}
_CAL = {}           # {user_id: calendar_service}
_ACCESS = {}        # {user_id: UserCredentials}

def gcs() -> storage.Client:
    global _GCS
    if _GCS is None:
        _GCS = storage.Client()
    return _GCS

def _delete_refresh_token(user_id: str):
    try:
        gcs().bucket(TOKEN_BUCKET).blob(_token_blob_path(user_id)).delete()
    except Exception:
        pass

def _get_creds_cached(user_id: str) -> Optional[UserCredentials]:
    prev = _ACCESS.get(user_id)
    if prev and prev.valid:
        return prev

    rt = load_refresh_token(user_id)
    if not rt:
        return None

    creds = UserCredentials(
        token=getattr(prev, "token", None) if prev else None,
        refresh_token=rt,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=OAUTH_CLIENT_ID,
        client_secret=OAUTH_CLIENT_SECRET,
        scopes=SCOPES,
    )
    try:
        if not creds.valid:
            creds.refresh(GoogleRequest())
    except RefreshError as e:
        msg = str(e)  # ← こっちの方が情報リッチで扱いやすい

        # ▼ 本当に再認証が必要なケースだけ refresh_token を削除
        if "invalid_grant" in msg or "invalid_client" in msg:
            _delete_refresh_token(user_id)
            _ACCESS.pop(user_id, None)
            return None  # → この場合だけユーザーに再認証を要求する

        # ▼ それ以外のエラーは「一時的なエラー」として扱う（トークンは残す）
        raise HTTPException(
            status_code=503,
            detail=f"Temporary OAuth refresh error: {msg}"
        )

    _ACCESS[user_id] = creds
    return creds
    
# ===== 追加: Pydantic models =====
try:
    from pydantic import ConfigDict  # v2
    V2 = True
except Exception:
    V2 = False

class AcronymSource(BaseModel):
    title: str | None = None
    url: AnyUrl | None = None

class AcronymCardModel(BaseModel):
    if V2:
        model_config = ConfigDict(extra='allow')
    else:
        class Config:
            extra = 'allow'
    term: str | None = None
    title: str | None = None
    description: str | None = None
    details: dict[str, Any] | None = None
    tags: list[str] | None = None
    sources: list[AcronymSource] | None = None

class AcronymCardsResponseModel(BaseModel):
    if V2:
        model_config = ConfigDict(extra='allow')
    else:
        class Config:
            extra = 'allow'
    cards: list[AcronymCardModel]
    count: int
    etag: str | None = None
    
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title="Study Plan API",
        version="1.5.0",
        description="",
        routes=app.routes,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["ServiceBearer"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "API Key",
    }
    # 全体に適用（各パスに 'authorization' ヘッダが必須だと解釈される）
    schema["security"] = [{"ServiceBearer": []}]
    # 認証不要エンドポイントは per-path で解除
    for p in ["/", "/health", "/oauth/start", "/oauth/callback", "/auth/status"]:
        if "paths" in schema and p in schema["paths"]:
            schema["paths"][p].setdefault("get", {}).setdefault("security", [])
    app.openapi_schema = schema
    return schema

app.openapi = custom_openapi

# ===== Health =====
def required_envs_ok() -> bool:
    return all([BASE_URL, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, APP_SECRET, TOKEN_BUCKET])

@app.get("/")
def root():
    return {"ok": True}

@app.get("/health")
def health():
    return {"ok": True, "env_ready": required_envs_ok()}


# ===== API Key Guard =====
def verify_api_key(request: Request, authorization: str = Header(None)):
    path = (request.url.path or "/").rstrip("/") or "/"
    if path in EXEMPT_PATHS:
        return
    expected = (SERVICE_API_KEY or "").strip()
    if not expected:
        raise HTTPException(500, "Server API key not configured")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(403, "Invalid API key")
    provided = authorization[7:].strip()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(403, "Invalid API key")


# ===== GCS Token Store =====
def _token_bucket() -> storage.Bucket:
    return gcs().bucket(TOKEN_BUCKET)

def _token_blob_path(user_id: str) -> str:
    safe = base64.urlsafe_b64encode(user_id.encode()).decode().rstrip("=")
    return f"tokens/{safe}.json"

def save_refresh_token(user_id: str, refresh_token: str):
    blob = _token_bucket().blob(_token_blob_path(user_id))
    data = {"user_id": user_id, "refresh_token": refresh_token, "updated_at": int(time.time())}
    blob.upload_from_string(json.dumps(data, ensure_ascii=False), content_type="application/json")

def load_refresh_token(user_id: str) -> Optional[str]:
    blob = _token_bucket().blob(_token_blob_path(user_id))
    try:
        data = json.loads(blob.download_as_text())
        return data.get("refresh_token")
    except Exception:
        return None

# ===== OAuth Flow =====
def oauth_redirect_uri() -> str:
    base = (BASE_URL or "").rstrip("/")
    if not base:
        raise RuntimeError("BASE_URL is not configured")
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
    return Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=oauth_redirect_uri())

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
        if len(parts) != 3:
            return None
        user_id = parts[0].decode()
        ts = int(parts[1].decode())
        sig_b64 = parts[2]
        expected = hmac.new(APP_SECRET.encode(), f"{user_id}|{ts}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(base64.urlsafe_b64encode(expected), sig_b64):
            return None
        if time.time() - ts > STATE_TTL:
            return None
        return user_id
    except Exception:
        return None
        
@app.get("/oauth/start")
def oauth_start(user_id: Optional[str] = None):
    if not required_envs_ok():
        return JSONResponse({"error": "OAuth env not set"}, status_code=500)
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)
    flow = build_flow()
    # PKCE推奨：google-auth-oauthlib Flow は自動でPKCE対応（code_challenge）する
    state = signed_state(user_id)
    save_oauth_state(state, {"user_id": user_id})
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        state=state,
    )
    return RedirectResponse(auth_url, status_code=302)

@app.get("/oauth/callback")
def oauth_callback(request: Request):
    if not required_envs_ok():
        return HTMLResponse("<h3>OAuth env not set</h3>", status_code=500)

    state = request.query_params.get("state", "")
    st = pop_oauth_state(state)
    user_id = (st or {}).get("user_id") or verify_state(state) or ""
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
            existing = load_refresh_token(user_id)
            if not existing:
                return HTMLResponse("<h3>⚠️ refresh_token が取得できませんでした。もう一度お試しください。</h3>", status_code=400)
            return HTMLResponse("<h3>✅ 連携済みです。チャットに戻って再実行してください。</h3>")
        save_refresh_token(user_id, rt)
        return HTMLResponse("<h3>✅ 連携が完了しました。チャットに戻って再実行してください。</h3>")
    except Exception as e:
        return HTMLResponse(f"<h3>OAuth error: {e}</h3>", status_code=400)

@app.get("/auth/status")
def auth_status(user_id: Optional[str] = None):
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)
    # 実際に取得/refresh まで試みて可否を返す
    ok = bool(_get_creds_cached(user_id))
    return {"user_id": user_id, "authorized": ok}

def load_user_credentials(user_id: str) -> Optional[UserCredentials]:
    return _get_creds_cached(user_id)

def get_user_sheets_service(user_id: str):
    if user_id in _SHEETS:
        return _SHEETS[user_id]
    creds = load_user_credentials(user_id)
    if not creds:
        return None
    svc = build("sheets", "v4", credentials=creds, cache_discovery=False)
    _SHEETS[user_id] = svc
    return svc

# ========= Calendar Service Helper =========
def get_user_calendar_service(user_id: str):
    if user_id in _CAL:
        return _CAL[user_id]
    creds = load_user_credentials(user_id)
    if not creds:
        return None
    svc = build("calendar", "v3", credentials=creds, cache_discovery=False)
    _CAL[user_id] = svc
    return svc

# ========= 日付/時刻ユーティリティ =========
def parse_ymd(s: str) -> Optional[datetime.date]:
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None

def _parse_hh_mm(s: str) -> Optional[datetime.time]:
    try:
        return datetime.strptime(s, "%H:%M").time()
    except Exception:
        return None

def start_of_week(d: datetime.date) -> datetime.date:
    # 月曜始まり（0=Mon）
    return d - timedelta(days=d.weekday())

def next_monday(today: Optional[datetime.date] = None) -> datetime.date:
    today = today or datetime.utcnow().date()
    n = (7 - today.weekday()) % 7
    n = 1 if n == 0 else n  # きょうが月曜でも次週の月曜に
    return today + timedelta(days=n)

def rfc3339(dt_date: datetime.date, hhmm: Optional[str]) -> Optional[str]:
    # hhmm が無ければ None（終日扱い）
    if not hhmm:
        return None
    return f"{dt_date.isoformat()}T{hhmm}:00{TZ_OFFSET}"

def make_event_id(user_id: str, wbs: str, date_str: str) -> str:
    raw = f"{user_id}|{wbs}|{date_str}".lower().encode()
    h = hashlib.sha1(raw).hexdigest()
    return f"gpts-{h}"

def _row_to_event_body(row: Dict[str, str]) -> Tuple[str, Dict[str, Any]]:
    date_str = (row.get("Date") or "").strip()
    task_name = (row.get("Task Name") or row.get("task") or "学習タスク").strip()
    status = (row.get("Status") or "").strip()
    note = (row.get("Note") or "").strip()
    start_hhmm = (row.get("Start") or row.get("start") or "").strip()
    end_hhmm = (row.get("End") or row.get("end") or "").strip()

    # Duration は数値/文字列どちらでも来るので str() を噛ませる
    try:
        duration_min = int(str(row.get("Duration", "0")).strip())
    except Exception:
        duration_min = None

    d = parse_ymd(date_str)
    if not d:
        raise ValueError("Invalid Date in row: expected YYYY-MM-DD")

    start_iso = rfc3339(d, start_hhmm)

    if start_iso:
        if end_hhmm:
            end_iso = rfc3339(d, end_hhmm)
        else:
            mins = duration_min if duration_min and duration_min > 0 else 60
            end_dt = datetime.strptime(f"{date_str} {start_hhmm}", "%Y-%m-%d %H:%M") + timedelta(minutes=mins)
            end_iso = f"{end_dt.strftime('%Y-%m-%dT%H:%M')}:00{TZ_OFFSET}"
        body = {
            "summary": task_name,
            "description": f"Status: {status}\nNote: {note}",
            "start": {"dateTime": start_iso, "timeZone": USER_TZ},
            "end": {"dateTime": end_iso, "timeZone": USER_TZ},
        }
    else:
        body = {
            "summary": f"{task_name}（終日）",
            "description": f"Status: {status}\nNote: {note}",
            "start": {"date": date_str},
            "end": {"date": (d + timedelta(days=1)).isoformat()},
        }

    return date_str, body
    
#=== Chapter items helpers (add) ===
def _gcs_get_json_or_default(bucket_name: str, blob_path: str, default):
    try:
        b = gcs().bucket(bucket_name).blob(blob_path)
        return json.loads(b.download_as_text())
    except Exception:
        return default

def expand_chapter_items(counts: List[int], titles: Optional[List[str]] = None) -> List[str]:
    items = []
    for i, c in enumerate(counts):
        base = titles[i].strip() if titles and i < len(titles) and titles[i] else f"Chapter {i+1}"
        for j in range(1, int(c) + 1):
            items.append(f"{base} - Item {j}")
    return items

def _load_chapter_items_from_gcs_or_none(book_filename: str) -> Optional[List[str]]:
    blob = gcs().bucket(BOOK_DATA_BUCKET).blob(book_filename)
    try:
        return json.loads(blob.download_as_text())  # NotFoundはexceptに落ちる
    except Exception:
        return None

def _normalize_chapter_items(data: dict, book_keyword: str) -> List[str]:

    # 1) payload 最優先
    if "chapter_items_list" in data and data["chapter_items_list"]:
        xs = data["chapter_items_list"]
        # ints の配列なら展開、strings の配列ならそのまま採用
        if all(isinstance(x, int) for x in xs):
            return expand_chapter_items(xs, None)
        if all(isinstance(x, str) for x in xs):
            return xs
        raise ValueError("chapter_items_list must be an array of integers or strings")

    if "chapter_counts" in data and data["chapter_counts"]:
        counts = [int(x) for x in data["chapter_counts"]]
        return expand_chapter_items(counts, None)

    if "chapters" in data and data["chapters"]:
        # ex: [{"title":"第1章 戦略","count":10}, {"title":"第2章 ...","count":12}]
        ch = data["chapters"]
        counts = []
        titles = []
        for obj in ch:
            counts.append(int(obj.get("count", 0)))
            titles.append(str(obj.get("title") or "").strip() or None)
        return expand_chapter_items(counts, titles)
        
    # 2) GCS フォールバック
    fallback = _load_chapter_items_from_gcs_or_none(f"{book_keyword}.json")
    if fallback:
        return fallback


    # 3) エラー
    raise ValueError(
        "Chapter data not found. Provide one of: chapter_items_list (ints or strings), "
        "chapter_counts (ints), or chapters ([{title,count},...])."
    )

# ===== Study Plan Core =====
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

@dataclass
class Task:
    WBS: str
    Task_Name: str
    Date: datetime
    Duration: int
    Status: str = "未着手"

    @property
    def Day(self) -> str:
        return DAY_ABBR[self.Date.weekday()]

# time allocation constants
MIN1 = 10
MIN2 = 7
MIN3 = 5

def weekday_abbr(d: datetime) -> str:
    return DAY_ABBR[d.weekday()]

def is_weekend(d: datetime) -> bool:
    return d.weekday() >= 5

def is_rest_day(d: datetime, rest_days: List[str]) -> bool:
    return weekday_abbr(d) in set(rest_days)

def next_day(d: datetime) -> datetime:
    return d + timedelta(days=1)

def calculate_available_time(user: UserSetting, date: datetime) -> int:
    d = date.date() if isinstance(date, datetime) else date
    # 休みロジック
    if DAY_ABBR[d.weekday()] in set(user.rest_days):
        return 0
    # 平日/週末で切替
    return user.weekend_minutes if d.weekday() >= 5 else user.weekday_minutes

class StudyPlanner:
    def __init__(self, user: UserSetting, chapter_items_list: List[str]):
        self.user = user
        self.chapter_items_list = chapter_items_list
        self.tasks: List[Task] = []
        self.wbs_counter = 0
        self.last_study_date: Optional[datetime] = None
        self.first_round_tasks: List[str] = []
        self.is_short = (self.user.target_exam - self.user.start_date).days <= 31

    def add_task(self, name: str, date: datetime, minutes: int):
        task = Task(f"wbs{self.wbs_counter}", name, date, minutes)
        self.tasks.append(task)
        self.wbs_counter += 1
        if self.last_study_date is None or date > self.last_study_date:
            self.last_study_date = date

    def allocate_tasks(self, tasks: List[Tuple[str, int]], start_date: datetime):
        current_date = start_date
        while tasks:
            if current_date > self.user.target_exam:
                break
            while calculate_available_time(self.user, current_date) == 0:
                current_date = next_day(current_date)
                if current_date > self.user.target_exam:
                    break
            available = calculate_available_time(self.user, current_date)
            while tasks and available >= tasks[0][1]:
                name, dur = tasks.pop(0)
                self.add_task(name, current_date, dur)
                available -= dur
            current_date = next_day(current_date)
        self.last_study_date = current_date
        return current_date

    def step0_setup(self):
        self.add_task("書籍の流し読みと概要把握", self.user.start_date, self.user.weekday_minutes)

    def step1_first_round(self):
        current_date = next_day(self.last_study_date)
        while self.chapter_items_list:
            available = calculate_available_time(self.user, current_date)
            while available >= MIN1 and self.chapter_items_list:
                name = self.chapter_items_list.pop(0)
                self.first_round_tasks.append(name)
                self.add_task(name, current_date, MIN1)
                available -= MIN1
            current_date = next_day(current_date)

    def step2_second_round(self):
        tasks = [(f"(2nd) {n}", MIN2) for n in self.first_round_tasks]
        self.allocate_tasks(tasks, next_day(self.last_study_date))

    def step3_first_exam(self):
        tasks = [("過去問 2025年 (1/2)", 60), ("過去問 2025年 (2/2)", 60), ("過去問 2025年 レビュー", 60)]
        self.allocate_tasks(tasks, next_day(next_day(self.last_study_date)))

    def step4_third_round(self):
        tasks = [(f"(3rd) {n}", MIN3) for n in self.first_round_tasks]
        self.allocate_tasks(tasks, next_day(self.last_study_date))

    def step5_weekend_reviews(self):
        current_date = self.user.start_date
        while current_date <= self.last_study_date:
            if current_date == self.user.start_date:
                current_date = next_day(current_date); continue
            day = weekday_abbr(current_date)
            if day == 'Sat':
                self.add_task("その週の復習", current_date, 60)
            elif day == 'Sun':
                self.add_task("アプリ演習と誤答復習", current_date, 60)
            current_date = next_day(current_date)

    def step6_refresh_days(self):
        current_date = next_day(self.last_study_date)
        for _ in range(2):
            self.add_task("リフレッシュ日", current_date, 0)
            current_date = next_day(current_date)

    def step7_past_exam_plan(self):
        YEARS = [2024, 2023, 2022, 2021, 2020, 2019, 2025]
        cutoff = self.user.target_exam - timedelta(days=1)
        start_date = next_day(self.last_study_date)

        def allocate_tasks_until(tasks, start_date, cutoff_date):
            current_date = start_date
            while tasks:
                if current_date > cutoff_date:
                    break
                while calculate_available_time(self.user, current_date) == 0:
                    current_date = next_day(current_date)
                    if current_date > cutoff_date:
                        break
                if current_date > cutoff_date:
                    break
                available = calculate_available_time(self.user, current_date)
                while tasks and available >= tasks[0][1]:
                    name, dur = tasks.pop(0)
                    self.add_task(name, current_date, dur)
                    available -= dur
                current_date = next_day(current_date)
            return current_date

        def year_tasks(y: int):
            return [
                (f"過去問 {y}年 (1/2)", 60),
                (f"過去問 {y}年 (2/2)", 60),
                (f"過去問 {y}年 レビュー", 60),
            ]

        for _round in range(3):
            if start_date > cutoff:
                break
            for y in YEARS:
                if start_date > cutoff:
                    break
                tasks = year_tasks(y)
                start_date = allocate_tasks_until(tasks, start_date, cutoff)
                if start_date > cutoff:
                    break
            if (not self.is_short) and (start_date <= cutoff):
                self.add_task("リフレッシュ日", start_date, 0)
                start_date = next_day(start_date)

        current_date = max(start_date, next_day(self.last_study_date))
        i = 1
        while current_date <= cutoff:
            if calculate_available_time(self.user, current_date) >= 60:
                self.add_task(f"過去問道場ランダム{i}", current_date, 60)
                i += 1
            current_date = next_day(current_date)

    def snapshot_raw_units(self) -> List[Dict[str, object]]:
        """
        step8で日別統合する『前』の self.tasks をそのまま JSON 化して返す。
        /day_off の再配分で利用する。
        """
        def _wbs_num(w: str) -> int:
            try:
                return int(str(w).replace("wbs", ""))
            except Exception:
                return 10**9
        items = []
        for t in sorted(self.tasks, key=lambda x: (x.Date, _wbs_num(x.WBS))):
            items.append({
                "WBS": t.WBS,
                "Task": t.Task_Name,
                "Date": t.Date.strftime("%Y-%m-%d"),
                "Day": t.Day,
                "Duration": t.Duration,
                "Status": t.Status,
                "meta": {
                    "round": ("3rd" if "(3rd)" in t.Task_Name else ("2nd" if "(2nd)" in t.Task_Name else "1st")),
                }
            })
        return items
    
    def step8_summarize_tasks(self):
        from collections import defaultdict
        grouped = defaultdict(list)
        for t in self.tasks:
            grouped[t.Date].append(t)

        new_tasks = []
        for date in sorted(grouped.keys()):
            tasks_for_day = grouped[date]
            normal = [t for t in tasks_for_day if "復習" not in t.Task_Name and "アプリ演習" not in t.Task_Name]
            review = [t for t in tasks_for_day if t not in normal]

            if len(normal) == 1:
                new_tasks.extend(normal)
            elif len(normal) > 1:
                first, last = normal[0], normal[-1]
                if "(2nd)" in first.Task_Name: lbl = "【2周】"
                elif "(3rd)" in first.Task_Name: lbl = "【3周】"
                elif "過去問" not in first.Task_Name and "レビュー" not in first.Task_Name: lbl = "【1周】"
                else: lbl = ""
                def clean(n): return n.replace("(2nd) ", "").replace("(3rd) ", "")
                combined = f"{lbl} {clean(first.Task_Name)} – {clean(last.Task_Name)}".strip()
                total = sum(t.Duration for t in normal)
                new_tasks.append(Task("", combined, date, total))
            new_tasks.extend(review)

        self.tasks = []
        for i, t in enumerate(sorted(new_tasks, key=lambda x: x.Date)):
            self.tasks.append(Task(f"wbs{i}", t.Task_Name, t.Date, t.Duration))

    def step9_merge_plan(self):
        self.plan_df = pd.DataFrame([{
            "WBS": t.WBS,
            "Task Name": t.Task_Name,
            "Date": t.Date.strftime('%Y-%m-%d'),
            "Day": t.Day,
            "Duration": t.Duration,
            "Status": t.Status
        } for t in self.tasks])
        self.plan_df.sort_values(by='Date', inplace=True)
        self.plan_df.reset_index(drop=True, inplace=True)
        self.plan_df['WBS'] = [f"wbs{i}" for i in range(len(self.plan_df))]

    def run_phase1(self):
        if not self.is_short:
            self.step0_setup()
        else:
            self.last_study_date = self.user.start_date - timedelta(days=1)
        self.step1_first_round()
        self.step3_first_exam()
        self.step2_second_round()
        self.step5_weekend_reviews()

    def run_phase2(self) -> List[Dict[str, object]]:
        if not self.is_short:
            self.step6_refresh_days()
        self.step7_past_exam_plan()
        raw_units = self.snapshot_raw_units()
        self.step8_summarize_tasks()
        self.step9_merge_plan()
        return raw_units


def generate_study_plan(data: dict, user_id: str) -> Tuple[pd.DataFrame, UserSetting, List[Dict[str, object]]]:
    user = UserSetting(
        user_id=user_id,
        target_exam=datetime.strptime(data["target_exam_date"], "%Y-%m-%d"),
        start_date=datetime.strptime(data["start_date"], "%Y-%m-%d"),
        weekday_minutes=int(data["weekday_minutes"]),
        weekend_minutes=int(data["weekend_minutes"]),
        rest_days=data.get("rest_days", ["Wed"]),
        weekday_start=data.get("weekday_start", "20:00"),
        weekend_start=data.get("weekend_start", "13:00"),
        book_keyword=data["book_keyword"],
    )
    try:
        chapter_items_list = _normalize_chapter_items(data, user.book_keyword)
    except Exception as e:
        raise ValueError(f"chapter items error: {e}")

    planner = StudyPlanner(user, chapter_items_list)
    
    # --- phase 1
    planner.run_phase1()
    raw_units = planner.run_phase2()

    return planner.plan_df, user, raw_units

# ===== Raw Plan Units backup (per spreadsheet_id) =====
def _raw_units_path(user_id: str, spreadsheet_id: str) -> str:
    # 1プラン=1スプレッドシートを前提に spreadsheet_id をキーに保存
    return f"gpts-plans/{user_id}/raw/{spreadsheet_id}.json"

def save_raw_plan_units_to_gcs(user_id: str, spreadsheet_id: str, raw_units: List[Dict[str, object]]) -> str:
    """
    "最小タスク単位"（統合前の1アイテム=10分/7分/5分や過去問など、step8でまとめる前の全行）を
    BACKUP_BUCKET に JSON として保存。
    """
    bucket = gcs().bucket(BACKUP_BUCKET)
    path = _raw_units_path(user_id, spreadsheet_id)
    blob = bucket.blob(path)
    blob.upload_from_string(json.dumps(raw_units, ensure_ascii=False), content_type="application/json")
    return f"gs://{BACKUP_BUCKET}/{path}"

def load_raw_plan_units_from_gcs(user_id: str, spreadsheet_id: str) -> Optional[List[Dict[str, object]]]:
    bucket = gcs().bucket(BACKUP_BUCKET)
    path = _raw_units_path(user_id, spreadsheet_id)
    blob = bucket.blob(path)
    if not blob.exists():
        return None
    try:
        return json.loads(blob.download_as_text())
    except Exception:
        return None

# === Raw Units: stable RID & WBS<->RID map helpers ===
def _ensure_rids(units: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """
    raw_units の各要素に安定ID 'RID' を付与（既存には触れない）。
    r1, r2, ... のようなシンプル連番。既存RIDは温存。
    """
    max_id = 0
    for u in units:
        rid = str(u.get("RID") or "").strip()
        if rid.startswith("r"):
            try:
                max_id = max(max_id, int(rid[1:]))
            except Exception:
                pass
    next_id = max_id + 1
    for u in units:
        if not str(u.get("RID") or "").strip():
            u["RID"] = f"r{next_id}"
            next_id += 1
    return units

def _wbs_raw_map_path(user_id: str, spreadsheet_id: str) -> str:
    return f"gpts-plans/{user_id}/maps/{spreadsheet_id}.json"

def save_wbs_raw_map(user_id: str, spreadsheet_id: str, mapping: Dict[str, List[str]]) -> str:
    """
    1表示行(WBS)が内包する raw RID の配列を保存するマップ。
    例: {"wbs0": ["r1","r2"], "wbs1": ["r3"]}
    """
    blob = gcs().bucket(BACKUP_BUCKET).blob(_wbs_raw_map_path(user_id, spreadsheet_id))
    blob.upload_from_string(json.dumps(mapping, ensure_ascii=False), content_type="application/json")
    return f"gs://{BACKUP_BUCKET}/{_wbs_raw_map_path(user_id, spreadsheet_id)}"

def load_wbs_raw_map(user_id: str, spreadsheet_id: str) -> Optional[Dict[str, List[str]]]:
    blob = gcs().bucket(BACKUP_BUCKET).blob(_wbs_raw_map_path(user_id, spreadsheet_id))
    try:
        return json.loads(blob.download_as_text())
    except Exception:
        return None

# === URL-backup helpers ===
def spreadsheet_web_url(spreadsheet_id: str) -> str:
    return f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}/edit#gid=0"

def _url_backup_object_name(user_id: str) -> str:
    return f"gpts-plans/{user_id}/history/url_backups.jsonl"

def append_url_backup(user_id: str, spreadsheet_id: str, spreadsheet_url: str, note: str = "") -> str:
    """
    シートURLの履歴を JSONL で1行追記する。
    例: gs://{BACKUP_BUCKET}/gpts-plans/{user_id}/history/url_backups.jsonl
    """
    bucket = gcs().bucket(BACKUP_BUCKET)
    obj = _url_backup_object_name(user_id)
    blob = bucket.blob(obj)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    rec = json.dumps({
        "ts": ts,
        "user_id": user_id,
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": spreadsheet_url,
        "note": note
    }, ensure_ascii=False) + "\n"

    if blob.exists():
        # compose で安全に追記
        tmp_name = f"{obj}.tmp.{ts}"
        tmp_blob = bucket.blob(tmp_name)
        tmp_blob.upload_from_string(rec, content_type="application/json")
        blob.compose([blob, tmp_blob])
        tmp_blob.delete()
    else:
        blob.upload_from_string(rec, content_type="application/json")
    return f"gs://{BACKUP_BUCKET}/{obj}"

# ===== Sheets/GCS ヘルパー =====
def write_tasks_to_sheet(spreadsheet_id: str, plan_df: pd.DataFrame, user_id: Optional[str] = None) -> None:
    """
    plan_df を A1 から全書換え（ヘッダ + データ）。ユーザーOAuthで実行。
    """
    service = get_user_sheets_service(user_id) if user_id else None
    if service is None:
        raise PermissionError("No OAuth tokens. Authorize first.")
    # 既存内容クリア（A:F）
    service.spreadsheets().values().clear(
        spreadsheetId=spreadsheet_id,
        range="A:F"
    ).execute()
    # ヘッダ
    service.spreadsheets().values().update(
        spreadsheetId=spreadsheet_id,
        range="A1",
        valueInputOption="RAW",
        body={"values": [list(plan_df.columns)]}
    ).execute()
    # データ
    if not plan_df.empty:
        service.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id,
            range="A2",
            valueInputOption="RAW",
            body={"values": plan_df.values.tolist()}
        ).execute()

# ===== Sheet I/O =====
def create_sheet_and_write(plan_df: pd.DataFrame, sheet_title: str, user_id: str) -> str:
    svc = get_user_sheets_service(user_id)
    if svc is None:
        raise PermissionError("No OAuth tokens. Authorize first.")

    # 新規作成
    sheet = svc.spreadsheets().create(
        body={"properties": {"title": sheet_title}}, fields="spreadsheetId"
    ).execute()
    spreadsheet_id = sheet.get("spreadsheetId")

    # ヘッダー + データ
    svc.spreadsheets().values().update(
        spreadsheetId=spreadsheet_id, range="A1", valueInputOption="RAW",
        body={"values": [list(plan_df.columns)]}
    ).execute()
    if not plan_df.empty:
        svc.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id, range="A2", valueInputOption="RAW",
            body={"values": plan_df.values.tolist()}
        ).execute()

    # 実シートID取得
    meta2 = svc.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
    first_sheet_id = meta2["sheets"][0]["properties"]["sheetId"]

    # 列幅調整（B列を広げる）
    try:
        svc.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={
                "requests": [{
                    "updateDimensionProperties": {
                        "range": {
                            "sheetId": first_sheet_id,
                            "dimension": "COLUMNS",
                            "startIndex": 1,   # B (0-based)
                            "endIndex": 2
                        },
                        "properties": {"pixelSize": 210},
                        "fields": "pixelSize"
                    }
                }]
            }
        ).execute()
    except Exception as e:
        print("[warn] 列幅設定に失敗:", e)

    # 条件付き書式（F列: Status）
    try:
        requests = [
            {
                "addConditionalFormatRule": {
                    "rule": {
                        "ranges": [{
                            "sheetId": first_sheet_id,
                            "startRowIndex": 1,
                            "startColumnIndex": 5,  # F
                            "endColumnIndex": 6
                        }],
                        "booleanRule": {
                            "condition": {"type": "TEXT_EQ", "values": [{"userEnteredValue": "完了"}]},
                            "format": {"backgroundColor": {"red": 0.85, "green": 0.95, "blue": 0.85}}
                        }
                    },
                    "index": 0
                }
            },
            {
                "addConditionalFormatRule": {
                    "rule": {
                        "ranges": [{
                            "sheetId": first_sheet_id,
                            "startRowIndex": 1,
                            "startColumnIndex": 5,
                            "endColumnIndex": 6
                        }],
                        "booleanRule": {
                            "condition": {
                                "type": "CUSTOM_FORMULA",
                                "values": [{"userEnteredValue": '=AND($F2<>"", $F2<>"完了")'}]
                 
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            },
                            "format": {"backgroundColor": {"red": 1.0, "green": 1.0, "blue": 0.85}}
                        }
                    },
                    "index": 0
                }
            }
        ]
        svc.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body={"requests": requests}).execute()
    except Exception as e:
        print("[warn] 条件付き書式の設定に失敗:", e)

    return spreadsheet_id


def generate_sheet_title(user: UserSetting) -> str:
    return f"user_{user.user_id}_plan_{user.start_date.strftime('%Y%m%d')}"

def load_user_sheet_map() -> Dict[str, Dict[str, str]]:
    return _gcs_get_json_or_default(USER_SHEET_MAP_BUCKET, USER_SHEET_MAP_BLOB, {})

def save_user_sheet_map(mapping: Dict[str, Dict[str, str]]) -> None:
    bucket = gcs().bucket(USER_SHEET_MAP_BUCKET)
    blob = bucket.blob(USER_SHEET_MAP_BLOB)
    blob.upload_from_string(json.dumps(mapping, ensure_ascii=False), content_type="application/json")

# ===== Endpoints =====
@app.post("/generate", dependencies=[Depends(verify_api_key)])
def generate_plan(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    # ---- OAuth check ----
    if not load_user_credentials(user_id):
        if not required_envs_ok():
            return JSONResponse({"error": "OAuth not configured on server"}, status_code=500)
        flow = build_flow()
        state = signed_state(user_id)
        save_oauth_state(state, {"user_id": user_id})

        auth_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            state=state
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Please authorize via the URL, then retry."
        }, status_code=200)

    # ---- Plan generation ----
    try:
        plan_df, user, raw_units = generate_study_plan(payload, user_id)  # 3 returns
    except Exception as e:
        return JSONResponse({"error": f"plan generation failed: {e}"}, status_code=400)

    # ---- NEW: ensure RID on raw ----
    raw_units = _ensure_rids(raw_units)   # ★ raw_units に RID 付与

    # ---- NEW: build plan_df again from raw to ensure full consistency ----
    plan_df, wmap = _summarize_units_with_map(raw_units)

    # ---- Write to Sheets ----
    try:
        spreadsheet_id = create_sheet_and_write(plan_df, generate_sheet_title(user), user_id)
    except PermissionError:
        flow = build_flow()
        state = signed_state(user_id)
        save_oauth_state(state, {"user_id": user_id})
        auth_url, _ = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent", state=state
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Authorization expired. Please re-authorize."
        }, status_code=200)
    except Exception as e:
        return JSONResponse({"error": f"Sheets error: {e}"}, status_code=500)

    # ---- Save raw units ----
    try:
        raw_uri = save_raw_plan_units_to_gcs(user.user_id, spreadsheet_id, raw_units)
    except Exception as e:
        print("[warn] save raw units failed:", e)
        raw_uri = None

    spreadsheet_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}"

    # ---- Save spreadsheet_id/url mapping ----
    try:
        mapping = load_user_sheet_map()
        mapping[user_id] = {"spreadsheet_id": spreadsheet_id, "spreadsheet_url": spreadsheet_url}
        save_user_sheet_map(mapping)
    except Exception as e:
        print("[warn] save mapping failed:", e)

    # ---- NEW: Save WBS→RID map ----
    try:
        save_wbs_raw_map(user_id, spreadsheet_id, wmap)
    except Exception as e:
        print("[warn] save_wbs_raw_map failed:", e)

    return {
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": spreadsheet_url,
        "raw_backup_uri": raw_uri
    }

def get_user_spreadsheet_id(user_id: str) -> Optional[str]:
    return (load_user_sheet_map().get(user_id) or {}).get("spreadsheet_id")

@app.post("/get_tasks", dependencies=[Depends(verify_api_key)])
def get_tasks(payload: dict = Body(...)):
    """
    認証確認 → 現行シートID解決 → {spreadsheet_id, spreadsheet_url} だけ返す
    """
    user_id = (payload.get("user_id") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    # 先に OAuth を確認（未認可なら authorize_url を返す）
    svc = get_user_sheets_service(user_id)
    if svc is None:
        if not required_envs_ok():
            return JSONResponse({"error": "OAuth not configured on server"}, status_code=500)
        flow = build_flow()
        state = signed_state(user_id)
        save_oauth_state(state, {"user_id": user_id})
        auth_url, _ = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent", state=state
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Authorization required. Please authorize via the URL, then retry."
        }, status_code=200)

    # 現行シートIDを mapping から取得
    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)

    # ここでは中身は返さず、リンクだけ返す
    return {
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": spreadsheet_web_url(spreadsheet_id),
    }
    
@app.post("/get_tasks_full", dependencies=[Depends(verify_api_key)])
def get_tasks_full(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    svc = get_user_sheets_service(user_id)
    if svc is None:
        if not required_envs_ok():
            return JSONResponse({"error": "OAuth not configured on server"}, status_code=500)
        flow = build_flow()
        state = signed_state(user_id)
        save_oauth_state(state, {"user_id": user_id})
        auth_url, _ = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent", state=state
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Authorization required. Please authorize via the URL, then retry."
        }, status_code=200)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)

    spreadsheet_url = spreadsheet_web_url(spreadsheet_id)

    try:
        meta = svc.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        sheet_title = meta["sheets"][0]["properties"]["title"]
        res = svc.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=f"{sheet_title}!A1:F1000"
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read sheet: {e}"}, status_code=500)

    values = res.get("values", [])
    if not values or len(values) < 2:
        return {
            "spreadsheet_id": spreadsheet_id,
            "spreadsheet_url": spreadsheet_url,
            "tasks": []
        }

    headers = values[0]
    rows = values[1:]
    tasks = [
        {headers[i]: (row[i] if i < len(row) else "") for i in range(len(headers))}
        for row in rows
        if any((c or "").strip() for c in row)
    ]
    return {
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": spreadsheet_url,
        "tasks": tasks
    }

# === New: Update task fields by WBS (single sheet) ===
@app.post("/update_task", dependencies=[Depends(verify_api_key)])
def update_task(payload: dict = Body(...)):
    """
    指定 WBS 行の任意フィールドを更新（複数フィールド対応）。単一シート前提。
    Allowed fields: Task Name, Date, Day, Duration, Status
    """
    user_id = (payload.get("user_id") or "").strip()
    wbs_id = (payload.get("wbs_id") or "").strip()
    if not user_id or not wbs_id:
        return JSONResponse({"error": "user_id and wbs_id are required"}, status_code=400)

    # 単発更新 or まとめ更新を正規化
    updates = payload.get("updates")
    if not updates:
        field = (payload.get("field") or "").strip()
        value = payload.get("value", "")
        if not field:
            return JSONResponse({"error": "Specify 'updates' or ('field' and 'value')"}, status_code=400)
        updates = {field: value}

    # WBS は更新禁止
    if "wbs" in [k.strip().lower() for k in updates.keys()]:
        return JSONResponse({"error": "Updating WBS is not allowed."}, status_code=400)

    # スプレッドシート解決
    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)

    svc = get_user_sheets_service(user_id)
    if svc is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    # シートタイトル取得
    try:
        meta = svc.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        sheet_title = meta["sheets"][0]["properties"]["title"]
    except Exception as e:
        return JSONResponse({"error": f"Failed to fetch sheet metadata: {e}"}, status_code=500)

    # 入力キーの正規化と検証
    normalized_updates = {}
    for k, v in updates.items():
        key_norm = (k or "").strip().lower()
        if key_norm not in FIELD_TO_COL:
            return JSONResponse(
                {"error": f"Unknown field '{k}'. Allowed: {list(FIELD_TO_COL.keys())}"},
                status_code=400
            )
        normalized_updates[key_norm] = v

    # WBS 行の検索（A列）
    try:
        rng_a = f"{sheet_title}!A2:A10000"
        got = svc.spreadsheets().values().get(spreadsheetId=spreadsheet_id, range=rng_a).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read WBS column: {e}"}, status_code=500)

    values = got.get("values", [])  # [[A2],[A3],...]
    row_index = None
    for i, row in enumerate(values):
        cell = (row[0] if row else "").strip()
        if cell == wbs_id:
            row_index = i + 2  # A2=2
            break
    if not row_index:
        return JSONResponse({"error": f"WBS ID '{wbs_id}' not found"}, status_code=404)

    # バッチ更新
    data_updates = []
    for field_lc, new_val in normalized_updates.items():
        col = FIELD_TO_COL[field_lc]
        a1 = f"{sheet_title}!{col}{row_index}"
        data_updates.append({"range": a1, "values": [[new_val]]})

    try:
        svc.spreadsheets().values().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={"valueInputOption": "RAW", "data": data_updates}
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Update failed: {e}"}, status_code=500)

    return {
        "message": "Task updated",
        "row": row_index,
        "updated_fields": list(normalized_updates.keys())
    }

# === New: Insert task by date ===
@app.post("/insert_task", dependencies=[Depends(verify_api_key)])
def insert_task(payload: dict = Body(...)):
    """
    指定された日付(必須)の位置に行を挿入し、タスクを追加する。
    その後、A列のWBSを先頭値に合わせて連番で振り直す。
    並びルール（asc）: C列(Date) 昇順。同一日付は末尾。
    """
    from datetime import datetime
    
    user_id = (payload.get("user_id") or "").strip()
    task_in = (payload.get("task") or {})
    order = (payload.get("order") or "asc").lower()
    if not user_id or not task_in:
        return JSONResponse({"error": "user_id and task are required"}, status_code=400)

    # 列構造に合わせて取り出し
    task_txt = (task_in.get("task") or "").strip()          # B: Task Name
    date_str = (task_in.get("date") or "").strip()          # C: Date
    day_str  = (task_in.get("day")  or "").strip()          # D: Day
    duration_raw = task_in.get("duration", "")              # E: Duration
    status   = (task_in.get("status") or "未着手").strip()  # F: Status
  
    ins_date = parse_ymd(date_str)
    if not ins_date:
        return JSONResponse({"error": "task.date must be 'YYYY-MM-DD'"}, status_code=400)
    if not day_str:
        day_str = DAY_ABBR[ins_date.weekday()]
    try:
        duration_val = int(str(duration_raw))
    except Exception:
        duration_val = 60  # デフォルト

    # ========== Spreadsheet / Sheet ==========
    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)
    service = get_user_sheets_service(user_id)
    if service is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)
    try:
        meta = service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        sheet = meta["sheets"][0]
        sheet_id = sheet["properties"]["sheetId"]
        sheet_title = sheet["properties"]["title"]
    except Exception as e:
        return JSONResponse({"error": f"Failed to fetch sheet metadata: {e}"}, status_code=500)

    # 既存データ（C列: Date）取得
    rng_c_all = f"{sheet_title}!C2:C10000"
    try:
        res = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=rng_c_all
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read existing rows: {e}"}, status_code=500)
    rows = res.get("values", [])

    # 挿入位置決定
    insert_row_1based = 2 + len(rows)
    if order == "asc":
        for i, r in enumerate(rows):
            r_date = parse_ymd((r[0] if r else "").strip())
            if r_date and ins_date < r_date:
                insert_row_1based = 2 + i
                break

    # 行挿入
    start_idx0 = insert_row_1based - 1
    end_idx0 = start_idx0 + 1
    try:
        service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={
                "requests": [{
                    "insertDimension": {
                        "range": {
                            "sheetId": sheet_id,
                            "dimension": "ROWS",
                            "startIndex": start_idx0,
                            "endIndex": end_idx0
                        },
                        "inheritFromBefore": True
                    }
                }]
            }
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Insert row failed: {e}"}, status_code=500)

    # 値書き込み
    try:
        service.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id,
            range=f"{sheet_title}!B{insert_row_1based}:F{insert_row_1based}",
            valueInputOption="RAW",
            body={"values": [[task_txt, date_str, day_str, str(duration_val), status]]}
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Write values failed: {e}"}, status_code=500)

    # A列のWBSふり直し
    try:
        resA = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=f"{sheet_title}!A2:A10000"
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read WBS column: {e}"}, status_code=500)
    a_vals = resA.get("values", [])

    def _wbs_start(a_first: str) -> int:
        try:
            return int((a_first or "").lower().replace("wbs", "").strip())
        except Exception:
            return 0

    start_num = _wbs_start((a_vals[0][0] if a_vals and a_vals[0] else "").strip()) if a_vals else 0
    new_wbs_col = [[f"wbs{start_num + i}"] for i in range(len(a_vals))]
    if new_wbs_col:
        try:
            service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_title}!A2:A{len(new_wbs_col)+1}",
                valueInputOption="RAW",
                body={"values": new_wbs_col}
            ).execute()
        except Exception as e:
            return JSONResponse({"error": f"Renumber WBS failed: {e}"}, status_code=500)

    inserted_wbs = f"wbs{start_num + (insert_row_1based - 2)}"
    return {
        "message": "Task inserted",
        "inserted_row": insert_row_1based,
        "wbs": inserted_wbs
    }

# === Delete by WBS (single/multiple) with RAW sync by RID-map ===
@app.post("/delete", dependencies=[Depends(verify_api_key)])
def delete_tasks(payload: dict = Body(...)):
    """
    body:
      {
        "user_id": "...",
        "wbs_id": "wbs12",              # 単数OK
        "wbs_ids": ["wbs12","wbs13"],   # 複数OK（wbs_id / wbs_ids どちらでも）
        "dry_run": false
      }
    挙動:
      - シートから対象行を一括削除（下から）
      - A列WBSを振り直し
      - RAWユニットは「削除対象WBSに寄与していたRID」を用いて除去して保存
        （_summarize_units_with_map を使用）
    """
    user_id = (payload.get("user_id") or "").strip()
    dry_run = bool(payload.get("dry_run", False))
    w1 = (payload.get("wbs_id") or "").strip()
    wN = payload.get("wbs_ids") or []
    wbs_ids = [w1] if (w1 and not wN) else (wN if wN else ([w1] if w1 else []))

    if not user_id or not wbs_ids:
        return JSONResponse({"error": "user_id and at least one of wbs_id/wbs_ids are required"}, status_code=400)

    # 正規化
    wset = {str(w).strip() for w in wbs_ids if str(w).strip()}
    if not wset:
        return JSONResponse({"error": "no valid WBS IDs"}, status_code=400)

    # 参照解決
    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)
    svc = get_user_sheets_service(user_id)
    if svc is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    # 現行シート読み込み
    try:
        meta = svc.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        sheet = meta["sheets"][0]
        sheet_id = sheet["properties"]["sheetId"]
        sheet_title = sheet["properties"]["title"]
        res = svc.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=f"{sheet_title}!A1:F10000"
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read sheet: {e}"}, status_code=500)

    values = res.get("values", [])
    if not values or len(values) < 2:
        # シートが空ならRAW側だけ同期（念のため全削除扱い）
        try:
            raw_units = load_raw_plan_units_from_gcs(user_id, spreadsheet_id) or []
            if raw_units:
                # WBS一致の行を落とす（RIDマップが作れないケースのフォールバック）
                kept = [u for u in raw_units if (str(u.get("WBS","")).strip() not in wset)]
                raw_uri = save_raw_plan_units_to_gcs(user_id, spreadsheet_id, kept)
            else:
                raw_uri = None
        except Exception as e:
            print("[warn] raw sync failed (empty sheet):", e)
            raw_uri = None
        return {"deleted": 0, "candidates": [], "raw_backup_uri": raw_uri}

    headers = values[0]
    rows = values[1:]

    # 対象行を特定（1-based 行番号）
    targets = []
    for i, r in enumerate(rows, start=2):
        w = (r[0] if r else "").strip()
        if w in wset:
            name = (r[headers.index("Task Name")] if "Task Name" in headers and len(r) > headers.index("Task Name") else "")
            date = (r[headers.index("Date")] if "Date" in headers and len(r) > headers.index("Date") else "")
            targets.append({"row": i, "WBS": w, "Task Name": name, "Date": date})

    if dry_run:
        return {"dry_run": True, "requested": list(wset), "found": len(targets), "candidates": targets}

    if not targets:
        return {"deleted": 0, "renumbered": False, "requested": list(wset)}

    # ===== RAW 側のRIDマッピングを先に作る =====
    # 現在の raw_units を読み込み → そこから「現在の集約結果」を再構築しWBS→RID[]マップを得る
    try:
        raw_units = load_raw_plan_units_from_gcs(user_id, spreadsheet_id) or []
        # 集約と寄与マップ（WBS -> [RID,...]）
        plan_df_map, wbs_map = _summarize_units_with_map(raw_units)  # ← 新ヘルパ
        # 削除対象WBSに寄与したRID集合
        rid_to_remove = set()
        for w in wset:
            for rid in wbs_map.get(w, []):
                rid_to_remove.add(rid)
    except Exception as e:
        print("[warn] build rid-map failed, fallback to WBS filter:", e)
        raw_units = raw_units if 'raw_units' in locals() else []
        rid_to_remove = None  # フォールバック

    # ===== Sheets 側で削除 =====
    requests = []
    for t in sorted(targets, key=lambda x: x["row"], reverse=True):
        start0 = t["row"] - 1
        requests.append({
            "deleteDimension": {
                "range": {"sheetId": sheet_id, "dimension": "ROWS", "startIndex": start0, "endIndex": start0 + 1}
            }
        })
    try:
        svc.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body={"requests": requests}).execute()
    except Exception as e:
        return JSONResponse({"error": f"Delete failed: {e}"}, status_code=500)

    # WBS 振り直し（A列）
    try:
        resA = svc.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=f"{sheet_title}!A2:A10000"
        ).execute()
        a_vals = resA.get("values", [])
        def _start(a0):
            try: return int((a0 or "").lower().replace("wbs","").strip())
            except: return 0
        start_num = _start((a_vals[0][0] if a_vals and a_vals[0] else "").strip()) if a_vals else 0
        new_wbs = [[f"wbs{start_num + i}"] for i in range(len(a_vals))]
        if new_wbs:
            svc.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_title}!A2:A{len(new_wbs)+1}",
                valueInputOption="RAW",
                body={"values": new_wbs}
            ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Renumber failed: {e}"}, status_code=500)

    # ===== RAW 同期：RIDベースで除去（失敗時はWBSフォールバック）=====
    raw_uri = None
    try:
        if rid_to_remove is not None:
            kept = []
            for i, u in enumerate(raw_units):
                rid = _unit_rid(u, i)  # ← 新ヘルパ
                if rid not in rid_to_remove:
                    kept.append(u)
        else:
            # フォールバック：WBS一致で除去（厳密性は落ちる）
            kept = [u for u in raw_units if (str(u.get("WBS","")).strip() not in wset)]

        raw_uri = save_raw_plan_units_to_gcs(user_id, spreadsheet_id, kept)
    except Exception as e:
        print("[warn] raw sync failed:", e)
        raw_uri = None

    return {
        "deleted": len(targets),
        "renumbered": True,
        "requested": list(wset),
        "raw_backup_uri": raw_uri
    }

# === Delete selected WBS then compact forward (RID-map safe) ===
@app.post("/delete_and_compact", dependencies=[Depends(verify_api_key)])
def delete_and_compact(payload: dict = Body(...)):
    """
    body:
      {
        "user_id": "...",
        "wbs_id": "wbs12",               # 単数OK
        "wbs_ids": ["wbs12","wbs13"],    # 複数OK
        "weekday_minutes": 60,
        "weekend_minutes": 180,
        "rest_days": ["Wed"],
        "dry_run": false
      }
    手順:
      1) RAWを読み込み → 集約＆WBS→RID[]マップを作る
      2) 指定WBSに寄与したRIDをRAWから除去
      3) 除去ユニットの最小日付 from_date から _redistribute_units_forward で前詰め
      4) まとめ直してシート上書き（WBS振り直し）＋ RAW保存
         ※ マップ生成に失敗時は WBS一致のフォールバックで除去
    """
    user_id = (payload.get("user_id") or "").strip()
    dry_run = bool(payload.get("dry_run", False))
    w1 = (payload.get("wbs_id") or "").strip()
    wN = payload.get("wbs_ids") or []
    wbs_ids = [w1] if (w1 and not wN) else (wN if wN else ([w1] if w1 else []))
    if not user_id or not wbs_ids:
        return JSONResponse({"error": "user_id and at least one of wbs_id/wbs_ids are required"}, status_code=400)

    weekday_minutes = int(payload.get("weekday_minutes", 60))
    weekend_minutes = int(payload.get("weekend_minutes", 180))
    rest_days = payload.get("rest_days") or []

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)

    # RAW取得（必須）
    raw_units = load_raw_plan_units_from_gcs(user_id, spreadsheet_id)
    if not raw_units:
        return JSONResponse({"error": "raw units not found. Please /generate or /regenerate first."}, status_code=409)

    # 正規化
    wset = {str(w).strip() for w in wbs_ids if str(w).strip()}
    if not wset:
        return JSONResponse({"error": "no valid WBS IDs"}, status_code=400)

    # 1) 集約＆WBS→RID[]マップ作成
    rid_to_remove = set()
    removed_dates = []
    try:
        # plan_df_map: 集約後のDF（WBS連番付与済）
        # wbs_map: { "wbsN": [rid1, rid2, ...] } どのRAWがどのWBSに寄与したか
        plan_df_map, wbs_map = _summarize_units_with_map(raw_units)
        for w in wset:
            for rid in wbs_map.get(w, []):
                rid_to_remove.add(rid)
        # 対象RIDの元RAWの日付を拾う（from_date算出用）
        def _p(s):
            try: return datetime.strptime(s, "%Y-%m-%d").date()
            except: return None
        for i, u in enumerate(raw_units):
            rid = _unit_rid(u, i)
            if rid in rid_to_remove:
                d = _p(str(u.get("Date","")).strip())
                if d: removed_dates.append(d)
    except Exception as e:
        # フォールバック：WBS一致でRAWを除去（厳密性は落ちる）
        print("[warn] rid-map build failed, fallback to WBS filter:", e)
        rid_to_remove = None
        def _p(s):
            try: return datetime.strptime(s, "%Y-%m-%d").date()
            except: return None
        # WBS一致ユニットを抽出
        for u in raw_units:
            if str(u.get("WBS","")).strip() in wset:
                d = _p(str(u.get("Date","")).strip())
                if d: removed_dates.append(d)

    # 2) RAWから除去
    if rid_to_remove is not None:
        kept = []
        for i, u in enumerate(raw_units):
            rid = _unit_rid(u, i)
            if rid not in rid_to_remove:
                kept.append(u)
        delete_count = len(raw_units) - len(kept)
    else:
        kept = [u for u in raw_units if (str(u.get("WBS","")).strip() not in wset)]
        delete_count = len(raw_units) - len(kept)

    # 対象無ければそのまま返す
    if delete_count <= 0:
        return {"deleted": 0, "compacted": False, "wbs": list(wset)}

    # 3) 前詰め開始日
    from_date = min(removed_dates) if removed_dates else None

    if dry_run:
        return {
            "dry_run": True,
            "wbs": list(wset),
            "delete_count": delete_count,
            "compact_from": from_date.isoformat() if from_date else None
        }

    # 4) 前詰め再配分 → 再集約
    new_units = _redistribute_units_forward(
        kept,
        from_date if from_date else (datetime.utcnow().date()),
        weekday_minutes=weekday_minutes,
        weekend_minutes=weekend_minutes,
        rest_days=rest_days
    )
    plan_df, _ = _summarize_units_with_map(new_units)

    # シート上書き（WBSは write_tasks_to_sheet 内で振り直された DF をそのまま保存）
    try:
        write_tasks_to_sheet(spreadsheet_id, plan_df, user_id)
    except Exception as e:
        return JSONResponse({"error": f"Sheets error: {e}"}, status_code=500)

    # RAW保存
    try:
        raw_uri = save_raw_plan_units_to_gcs(user_id, spreadsheet_id, new_units)
    except Exception as e:
        print("[warn] save raw failed:", e)
        raw_uri = None

    return {
        "ok": True,
        "wbs": list(wset),
        "deleted": delete_count,
        "compact_from": from_date.isoformat() if from_date else None,
        "spreadsheet_id": spreadsheet_id,
        "raw_backup_uri": raw_uri,
        "preview_head": plan_df.head(10).to_dict(orient="records")
    }
    
# === New: Preview tasks for a week ===
@app.post("/preview_week", dependencies=[Depends(verify_api_key)])
def preview_week(payload: dict = Body(...)):
    """
    指定 week_of(YYYY-MM-DDのどこかの日) を含む週の予定を返す。
    無指定なら「次週の月〜日」。
    返却キー: WBS, Date, Start, End, Task Name, Status, Note など（シートの列に依存）
    """
    user_id = (payload.get("user_id") or "").strip()
    week_of = (payload.get("week_of") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)
    svc = get_user_sheets_service(user_id)
    if svc is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    try:
        meta = svc.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        sheet_title = meta["sheets"][0]["properties"]["title"]
        res = svc.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=f"{sheet_title}!A1:G10000"
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read sheet: {e}"}, status_code=500)

    values = res.get("values", [])
    if not values or len(values) < 2:
        return {"tasks": []}

    headers = values[0]
    rows = values[1:]

    if week_of:
        base = parse_ymd(week_of) or datetime.utcnow().date()
        monday = start_of_week(base)
    else:
        monday = next_monday()
    sunday = monday + timedelta(days=6)

    out = []
    for r in rows:
        row = {headers[i]: (r[i] if i < len(r) else "") for i in range(len(headers))}
        d = parse_ymd((row.get("Date") or "").strip())
        if d and monday <= d <= sunday:
            out.append(row)

    return {
        "week": {"start": monday.isoformat(), "end": sunday.isoformat()},
        "tasks": out
    }

# === New: Register a week's tasks to Google Calendar ===
@app.post("/calendar/register_week", dependencies=[Depends(verify_api_key)])
def calendar_register_week(payload: dict = Body(...)):
    """
    指定週のタスクを Google カレンダーに登録/更新。
    body:
      {
        "user_id": "...",
        "week_of": "YYYY-MM-DD",   # 任意。未指定なら次週
        "calendar_id": "primary",  # 任意
        "dry_run": false           # 任意。trueなら作成せず差分だけ返す
      }
    """
    user_id = (payload.get("user_id") or "").strip()
    week_of = (payload.get("week_of") or "").strip()
    calendar_id = (payload.get("calendar_id") or "primary").strip()
    dry_run = bool(payload.get("dry_run", False))
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    # 週次データ取得（preview_week と同等ロジック）
    prev = preview_week({"user_id": user_id, "week_of": week_of})  # FastAPI内の直接呼び出し
    # preview_week は dict を返す契約（上でそう実装）
    if isinstance(prev, JSONResponse):
        return prev
    tasks = prev.get("tasks", [])
    week = prev.get("week", {})
    if not tasks:
        return {"message": "No tasks in the target week", "week": week, "created": [], "updated": [], "skipped": []}

    cal = get_user_calendar_service(user_id)
    if cal is None:
        flow = build_flow()
        auth_url, _ = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent",
            state=signed_state(user_id)
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Calendar authorization required. Please authorize and retry."
        }, status_code=200)

    created, updated, skipped = [], [], []
    for row in tasks:
        wbs = (row.get("WBS") or "").strip()

        # ★ここから差し替え
        date_str, body = _row_to_event_body(row)

        # 固有の拡張プロパティだけ後付け
        body.setdefault("extendedProperties", {}).setdefault("private", {})
        body["extendedProperties"]["private"].update({"gpts_wbs": wbs, "gpts_date": date_str})

        ev_id = make_event_id(user_id, wbs or "no-wbs", date_str or "no-date")
        if dry_run:
            skipped.append({"id": ev_id, "title": body.get("summary", ""), "date": date_str})
            continue

        try:
            cal.events().update(
                calendarId=calendar_id,
                eventId=ev_id,
                body=body,
                sendUpdates="none"
            ).execute()
            updated.append({"id": ev_id, "title": body.get("summary", ""), "date": date_str})
        except Exception as e_upd:
            # 新規作成（importは body['id'] を尊重）
            try:
                body_with_id = dict(body)
                body_with_id["id"] = ev_id
                cal.events().import_(
                    calendarId=calendar_id,
                    body=body_with_id
                ).execute()
                created.append({"id": ev_id, "title": body.get("summary", ""), "date": date_str})
            except Exception as e_imp:
                skipped.append({"id": ev_id, "error": f"import failed: {e_imp}"})
    return {
        "week": week,
        "calendar_id": calendar_id,
        "created": created,
        "updated": updated,
        "skipped": skipped
    }

# === New: Register/update specific WBS rows to Calendar ===
@app.post("/calendar/register_by_wbs", dependencies=[Depends(verify_api_key)])
def calendar_register_by_wbs(payload: dict = Body(...)):
    """
    指定された WBS 行だけを登録/更新。
    body:
      {
        "user_id": "...",
        "wbs_ids": ["wbs12","wbs13"],
        "calendar_id": "primary",
        "dry_run": false
      }
    """
    user_id = (payload.get("user_id") or "").strip()
    wbs_ids = payload.get("wbs_ids") or []
    calendar_id = (payload.get("calendar_id") or "primary").strip()
    dry_run = bool(payload.get("dry_run", False))
    if not user_id or not wbs_ids:
        return JSONResponse({"error": "user_id and wbs_ids are required"}, status_code=400)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)
    svc = get_user_sheets_service(user_id)
    if svc is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    try:
        meta = svc.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        sheet_title = meta["sheets"][0]["properties"]["title"]
        res = svc.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=f"{sheet_title}!A1:G10000"
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read sheet: {e}"}, status_code=500)

    values = res.get("values", [])
    if not values or len(values) < 2:
        return JSONResponse({"error": "no tasks"}, status_code=404)

    headers = values[0]
    rows = values[1:]

    target = []
    wset = set(wbs_ids)
    for r in rows:
        row = {headers[i]: (r[i] if i < len(r) else "") for i in range(len(headers))}
        if (row.get("WBS") or "").strip() in wset:
            target.append(row)
    if not target:
        return JSONResponse({"error": "specified WBS not found"}, status_code=404)

    cal = get_user_calendar_service(user_id)
    if cal is None:
        flow = build_flow()
        auth_url, _ = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent",
            state=signed_state(user_id)
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Calendar authorization required. Please authorize and retry."
        }, status_code=200)

    created, updated, skipped = [], [], []
    for row in target:
        wbs = (row.get("WBS") or "").strip()

        # ★ここから差し替え
        date_str, body = _row_to_event_body(row)

        body.setdefault("extendedProperties", {}).setdefault("private", {})
        body["extendedProperties"]["private"].update({"gpts_wbs": wbs, "gpts_date": date_str})

        ev_id = make_event_id(user_id, wbs or "no-wbs", date_str or "no-date")
        if dry_run:
            skipped.append({"id": ev_id, "title": body.get("summary", ""), "date": date_str})
            continue

    # 置き換え：insert をやめて update→import の順に
        try:
            cal.events().update(
                calendarId=calendar_id, eventId=ev_id, body=body, sendUpdates="none"
            ).execute()
            updated.append({"id": ev_id, "title": body.get("summary", ""), "date": date_str})
        except Exception as e_upd:
            try:
                body_with_id = dict(body); body_with_id["id"] = ev_id
                cal.events().import_(
                    calendarId=calendar_id,
                    body=body_with_id
                ).execute()
                created.append({"id": ev_id, "title": body.get("summary", ""), "date": date_str})
            except Exception as e_imp:
                skipped.append({"id": ev_id, "error": f"import failed: {e_imp}"})
                
    return {
        "calendar_id": calendar_id,
        "created": created,
        "updated": updated,
        "skipped": skipped
    }

# === URL history backup & Regenerate ===
@app.post("/backup", dependencies=[Depends(verify_api_key)])
def backup_only(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    note = (payload.get("note") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)

    spreadsheet_url = spreadsheet_web_url(spreadsheet_id)
    try:
        hist_uri = append_url_backup(user_id, spreadsheet_id, spreadsheet_url, note=note)
        return {
            "ok": True,
            "history_uri": hist_uri,
            "spreadsheet_id": spreadsheet_id,
            "spreadsheet_url": spreadsheet_url
        }
    except Exception as e:
        return JSONResponse({"error": f"backup failed: {e}"}, status_code=500)

@app.get("/backup/list", dependencies=[Depends(verify_api_key)])
def list_url_backups(user_id: str):
    """
    URLバックアップ履歴を返す（新しい順）
    """
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    obj = _url_backup_object_name(user_id)
    try:
        text = gcs().bucket(BACKUP_BUCKET).blob(obj).download_as_text()
    except Exception:
        return {"items": []}
    try:
        lines = text.splitlines()
        items = [json.loads(x) for x in lines if x.strip()]
        items.sort(key=lambda r: r.get("ts", ""), reverse=True)
        return {"items": items}
    except Exception as e:
        return JSONResponse({"error": f"list failed: {e}"}, status_code=500)


@app.post("/backup/switch_active", dependencies=[Depends(verify_api_key)])
def switch_active_sheet(payload: dict = Body(...)):
    """
    履歴にある spreadsheet_id を「現行」として mapping.json を更新する。
    body: { "user_id":"...", "spreadsheet_id":"..." }
    """
    user_id = (payload.get("user_id") or "").strip()
    spreadsheet_id = (payload.get("spreadsheet_id") or "").strip()
    if not user_id or not spreadsheet_id:
        return JSONResponse({"error": "user_id and spreadsheet_id are required"}, status_code=400)

    spreadsheet_url = spreadsheet_web_url(spreadsheet_id)
    try:
        mapping = load_user_sheet_map()
        mapping[user_id] = {
            "spreadsheet_id": spreadsheet_id,
            "spreadsheet_url": spreadsheet_url
        }
        save_user_sheet_map(mapping)
        return {"ok": True, "spreadsheet_id": spreadsheet_id, "spreadsheet_url": spreadsheet_url}
    except Exception as e:
        return JSONResponse({"error": f"switch failed: {e}"}, status_code=500)

@app.post("/regenerate", dependencies=[Depends(verify_api_key)])
def regenerate_and_overwrite(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)

    # ---- OAuth check ----
    if not load_user_credentials(user_id):
        if not required_envs_ok():
            return JSONResponse({"error": "OAuth not configured on server"}, status_code=500)
        flow = build_flow()
        auth_url, _ = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent", state=signed_state(user_id)
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Please authorize via the URL, then retry."
        }, status_code=200)

    # ---- New plan generation ----
    try:
        plan_df, user, raw_units = generate_study_plan(payload, user_id)
    except Exception as e:
        return JSONResponse({"error": f"plan generation failed: {e}"}, status_code=400)

    # === NEW: raw に RID 付与 ===
    raw_units = _ensure_rids(raw_units)

    # === NEW: raw_units から再サマリして plan_df + WBS→RID map を生成 ===
    plan_df, wmap = _summarize_units_with_map(raw_units)

    spreadsheet_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}"

    # ---- Write sheet backup history ----
    try:
        history_uri = append_url_backup(user.user_id, spreadsheet_id, spreadsheet_url, note="regenerate-before-overwrite")
    except Exception as e:
        print("[warn] append_url_backup failed:", e)
        history_uri = None

    # ---- Write updated plan to Sheets ----
    try:
        write_tasks_to_sheet(spreadsheet_id, plan_df, user.user_id)
    except Exception as e:
        return JSONResponse({"error": f"Sheets error: {e}"}, status_code=500)

    # ---- Save raw units ----
    try:
        raw_backup_uri = save_raw_plan_units_to_gcs(user.user_id, spreadsheet_id, raw_units)
    except Exception as e:
        print("[warn] save raw units failed:", e)
        raw_backup_uri = None

    # ---- NEW: Save WBS→RID map ----
    try:
        save_wbs_raw_map(user_id, spreadsheet_id, wmap)
    except Exception as e:
        print("[warn] save_wbs_raw_map failed:", e)

    return {
        "ok": True,
        "history_uri": history_uri,
        "raw_backup_uri": raw_backup_uri,
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": spreadsheet_url,
        "plan_preview": plan_df.head(5).to_dict(orient="records")
    }

# === Day-off reflow helpers ===
def _parse_date(s: str):
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None

def _wbs_num(w: str) -> int:
    try:
        return int(str(w).replace("wbs", "").strip())
    except Exception:
        return 10**9

def _is_review_task(name: str) -> bool:
    """サマリーで『結合しない』特殊タスクを判定"""
    n = (name or "").strip()
    if not n:
        return False
    return ("復習" in n) or ("アプリ演習" in n) or (n == "リフレッシュ日")
    
def _capacity_for_date(d: datetime.date, weekday_minutes: int, weekend_minutes: int,
                       rest_days: List[str], off_date: datetime.date,
                       repeat_weekday: bool) -> int:
    # 明示の休み日
    if d == off_date:
        return 0
    # 固定休み（既存設定 + 今回の曜日を固定化するオプション）
    abbr = DAY_ABBR[d.weekday()]
    if abbr in set(rest_days):
        return 0
    if repeat_weekday and d.weekday() == off_date.weekday():
        return 0
    # それ以外は平日/休日の持ち時間
    return weekend_minutes if d.weekday() >= 5 else weekday_minutes

def _redistribute_units_after_day_off(
    raw_units: List[Dict[str, object]],
    off_date: datetime.date,
    weekday_minutes: int,
    weekend_minutes: int,
    rest_days: List[str],
    repeat_weekday: bool = False
) -> List[Dict[str, object]]:
    """
    raw_units（step8統合前の最小単位）を、off_date 以降について再配分する。

    - off_date より前は手を付けない
    - off_date 当日は容量0
    - repeat_weekday=True の場合、off_date の曜日を以降ずっと休みにする
    - 1ユニットの分割はしない（生成時の最小単位を保つ）
    """

    def u_date(u):
        return _parse_date(str(u.get("Date", "")).strip())

    # 安定ソートキー（元の順序を最大限維持）
    def key(u):
        return (
            u_date(u) or datetime(1970, 1, 1).date(),
            _wbs_num(str(u.get("WBS", "wbs999999")))
        )

    # 前半（off_date より前）はそのまま、後半（off_date 以降）を再配分
    before = [u for u in raw_units if (u_date(u) and u_date(u) < off_date)]
    tail = [u for u in raw_units if (u_date(u) and u_date(u) >= off_date)]
    tail.sort(key=key)

    # 再配分開始
    cur = off_date
    i = 0
    reassigned = []

    while i < len(tail):
        cap = _capacity_for_date(
            cur,
            weekday_minutes,
            weekend_minutes,
            rest_days,
            off_date,
            repeat_weekday
        )

        if cap <= 0:
            cur = cur + timedelta(days=1)
            continue

        used = 0
        while i < len(tail):
            dur = 0
            try:
                dur = int(tail[i].get("Duration", 0))
            except Exception:
                dur = 0

            if dur <= 0:  # 異常値はスキップ
                u = tail[i].copy()
                u["Date"] = cur.isoformat()
                reassigned.append(u)
                i += 1
                continue

            if used + dur <= cap:
                u = tail[i].copy()
                u["Date"] = cur.isoformat()
                reassigned.append(u)
                used += dur
                i += 1
            else:
                break  # 次の日へ

        cur = cur + timedelta(days=1)

    return before + reassigned

def _redistribute_units_forward(
    raw_units: List[Dict[str, object]],
    from_date: datetime.date,
    weekday_minutes: int,
    weekend_minutes: int,
    rest_days: List[str],
) -> List[Dict[str, object]]:
    def _p(s):
        try: return datetime.strptime(s, "%Y-%m-%d").date()
        except: return None
    def _key(u):
        d = _p(str(u.get("Date","")).strip()) or datetime(1970,1,1).date()
        try: n = int(str(u.get("WBS","wbs999999")).replace("wbs","").strip())
        except: n = 10**9
        return (d, n)

    before = [u for u in raw_units if _p(u.get("Date","")) and _p(u["Date"]) < from_date]
    tail   = [u for u in raw_units if _p(u.get("Date","")) and _p(u["Date"]) >= from_date]
    tail.sort(key=_key)

    cur = from_date
    i = 0
    out = []
    while i < len(tail):
        cap = _capacity_for_date(cur, weekday_minutes, weekend_minutes, rest_days, off_date=from_date, repeat_weekday=False)
        if cap <= 0:
            cur = cur + timedelta(days=1); continue
        used = 0
        while i < len(tail):
            try: dur = int(tail[i].get("Duration", 0))
            except: dur = 0
            u = tail[i].copy(); u["Date"] = cur.isoformat()
            if dur <= 0 or used + dur <= cap:
                out.append(u); used += max(dur, 0); i += 1
            else:
                break
        cur = cur + timedelta(days=1)
    return before + out

# 残す: 安定ID生成（新規）
def _unit_rid(u: Dict[str, object], idx: int) -> str:
    rid = str(u.get("RID") or "").strip()
    if rid:
        return rid
    w = str(u.get("WBS","")).strip()
    t = str(u.get("Task","")).strip()
    d = str(u.get("Date","")).strip()
    return f"{w}|{d}|{t}|{idx}"

# 置き換え: _summarize_units_with_map 内で _is_review_task を使用
def _summarize_units_with_map(units: List[Dict[str, object]]) -> Tuple[pd.DataFrame, Dict[str, List[str]]]:
    from collections import defaultdict
    class _T:
        __slots__ = ("rid","WBS","Task_Name","Date","Duration","Status")
        def __init__(self, rid, WBS, name, date_str, dur, status):
            self.rid = rid
            self.WBS = WBS
            self.Task_Name = name
            self.Date = datetime.strptime(date_str, "%Y-%m-%d")
            self.Duration = int(dur) if str(dur).isdigit() else 0
            self.Status = status or "未着手"
        @property
        def Day(self): return DAY_ABBR[self.Date.weekday()]

    tasks = []
    for i, u in enumerate(units):
        tasks.append(_T(
            _unit_rid(u, i),
            str(u.get("WBS","")),
            str(u.get("Task","")),
            str(u.get("Date","")).strip(),
            u.get("Duration", 0),
            str(u.get("Status","未着手"))
        ))

    grouped = defaultdict(list)
    for t in tasks:
        grouped[t.Date.date()].append(t)

    new_rows, contrib = [], []
    for date in sorted(grouped.keys()):
        day_tasks = grouped[date]
        normal = [t for t in day_tasks if not _is_review_task(t.Task_Name)]  # ←ここだけ
        review = [t for t in day_tasks if t not in normal]

        if len(normal) == 1:
            t = normal[0]
            new_rows.append({"WBS":"", "Task Name": t.Task_Name, "Date": t.Date.strftime('%Y-%m-%d'),
                             "Day": t.Day, "Duration": t.Duration, "Status": t.Status})
            contrib.append([t.rid])
        elif len(normal) > 1:
            first, last = normal[0], normal[-1]
            if "(2nd)" in first.Task_Name: lbl = "【2周】"
            elif "(3rd)" in first.Task_Name: lbl = "【3周】"
            elif "過去問" not in first.Task_Name and "レビュー" not in first.Task_Name: lbl = "【1周】"
            else: lbl = ""
            def clean(n): return n.replace("(2nd) ", "").replace("(3rd) ", "")
            combined = f"{lbl} {clean(first.Task_Name)} – {clean(last.Task_Name)}".strip()
            total = sum(t.Duration for t in normal)
            new_rows.append({"WBS":"", "Task Name": combined, "Date": first.Date.strftime('%Y-%m-%d'),
                             "Day": first.Day, "Duration": total, "Status": "未着手"})
            contrib.append([t.rid for t in normal])

        for t in review:
            new_rows.append({"WBS":"", "Task Name": t.Task_Name, "Date": t.Date.strftime('%Y-%m-%d'),
                             "Day": t.Day, "Duration": t.Duration, "Status": t.Status})
            contrib.append([t.rid])

    if new_rows:
        plan_df = pd.DataFrame(new_rows)
        plan_df.reset_index(drop=True, inplace=True)
        plan_df["WBS"] = [f"wbs{i}" for i in range(len(plan_df))]
        wbs_map = {f"wbs{i}": contrib[i] for i in range(len(plan_df))}
    else:
        plan_df = pd.DataFrame(columns=["WBS","Task Name","Date","Day","Duration","Status"])
        wbs_map = {}

    return plan_df[["WBS","Task Name","Date","Day","Duration","Status"]], wbs_map
    
# === New: Day-off endpoint ===
@app.post("/day_off", dependencies=[Depends(verify_api_key)])
def day_off(payload: dict = Body(...)):
    """
    指定日のタスクを削除せず『以降に先送り』して再配分する。
    入力:
      {
        "user_id": "...",
        "off_date": "YYYY-MM-DD",
        "weekday_minutes": 60,
        "weekend_minutes": 180,
        "rest_days": ["Wed"],      # 既存の固定休み（任意）
        "repeat_weekday": false    # trueなら off_date の曜日を以降ずっと休みに
      }
    流れ:
      1) raw_units を GCS から取得
      2) off_date 以降を容量計算で再配分
      3) まとめ直してシート全体を書き換え（WBSは振り直し）
      4) 新しい raw_units を GCS に保存
    """
    user_id = (payload.get("user_id") or "").strip()
    off_date_str = (payload.get("off_date") or "").strip()
    if not user_id or not off_date_str:
        return JSONResponse({"error": "user_id and off_date are required"}, status_code=400)

    weekday_minutes = int(payload.get("weekday_minutes", 60))
    weekend_minutes = int(payload.get("weekend_minutes", 120))
    rest_days = payload.get("rest_days") or []
    repeat_weekday = bool(payload.get("repeat_weekday", False))

    d0 = _parse_date(off_date_str)
    if not d0:
        return JSONResponse({"error": "off_date must be 'YYYY-MM-DD'"}, status_code=400)

    # スプレッドシート解決
    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)
    svc = get_user_sheets_service(user_id)
    if svc is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    # raw units 読み込み
    raw_units = load_raw_plan_units_from_gcs(user_id, spreadsheet_id)
    if not raw_units:
        return JSONResponse(
            {"error": "raw units not found. Please /regenerate or /generate to create raw backup first."},
            status_code=409
        )

    # 再配分
    new_units = _redistribute_units_after_day_off(
        raw_units=raw_units,
        off_date=d0,
        weekday_minutes=weekday_minutes,
        weekend_minutes=weekend_minutes,
        rest_days=rest_days,
        repeat_weekday=repeat_weekday
    )

    # まとめ直して plan_df を作る
    plan_df, _ = _summarize_units_with_map(new_units)

    # シート上書き
    try:
        write_tasks_to_sheet(spreadsheet_id, plan_df, user_id)
    except Exception as e:
        return JSONResponse({"error": f"Sheets error: {e}"}, status_code=500)

    # raw を上書き保存（次回の day_off に備える）
    try:
        raw_backup_uri = save_raw_plan_units_to_gcs(user_id, spreadsheet_id, new_units)
    except Exception as e:
        print("[warn] save raw units failed:", e)
        raw_backup_uri = None

    # サマリーを返却
    # どれだけ動いたか（分/件）
    def minutes(xs):
        s = 0
        for u in xs:
            try:
                s += int(u.get("Duration", 0))
            except Exception:
                pass
        return s

    moved = [u for u in raw_units if _parse_date(u.get("Date","")) >= d0]
    return {
        "ok": True,
        "spreadsheet_id": spreadsheet_id,
        "raw_backup_uri": raw_backup_uri,
        "off_date": off_date_str,
        "repeat_weekday": repeat_weekday,
        "moved_units_count": len(moved),
        "moved_minutes_total": minutes(moved),
        "preview_head": plan_df.head(10).to_dict(orient="records")
    }

def _ac_load_from_gcs(force: bool = False):
    now = time.time()
    if not force and (now - _AC_CACHE["last"] < ACRONYM_REFRESH_SEC) and _AC_CACHE["terms"]:
        return

    blob = gcs().bucket(ACRONYM_BUCKET).blob(ACRONYM_PATH)
    # 変更検知（ETag）: blob.reload() の失敗を握りつぶして空キャッシュ
    try:
        blob.reload()
    except Exception:
        _AC_CACHE.update({"terms": {}, "last": now, "etag": None})
        return

    etag = getattr(blob, "etag", None)
    if not force and _AC_CACHE["etag"] and etag == _AC_CACHE["etag"]:
        _AC_CACHE["last"] = now
        return

    data = blob.download_as_text()
    obj = json.loads(data)  # { "DNS": {...}, ... }

    terms = {}
    for k, card in obj.items():
        key = (k or "").upper()
        if key:
            terms[key] = card

    _AC_CACHE.update({"terms": terms, "last": now, "etag": etag})


def _ac_get(term: str):
    _ac_load_from_gcs()
    return _AC_CACHE["terms"].get((term or "").upper())


@app.get("/acronyms/session", dependencies=[Depends(verify_api_key)],
         response_model=AcronymCardsResponseModel)
def get_acronym_session(count: int = 10, shuffle: bool = True):
    """
    学習用に複数カードをまとめて返す（デフォルト10件）
    例: GET /acronyms/session?count=10
    """
    if count < 1:
        count = 1
    if count > 30:
        count = 30
    _ac_load_from_gcs()
    items = list(_AC_CACHE["terms"].values())
    if shuffle:
        random.shuffle(items)
    picked = items[:count]
    return {"cards": picked, "count": len(picked), "etag": _AC_CACHE["etag"]}

@app.post("/books/register", dependencies=[Depends(verify_api_key)])
def register_book_chapters(payload: dict = Body(...)):
    """
    任意の書籍キーワードに対応する章データ（項目名の配列）を GCS に保存する。
    body 例:
      {
        "book_keyword": "kayanoki",
        # 以下のいずれか:
        "chapter_items_list": [12, 10, 8],       # ints -> 展開 / strings -> そのまま
        "chapter_counts": [12, 10, 8],           # ints
        "chapters": [{"title":"第1章 戦略","count":12}, ...],
        "overwrite": false
      }
    保存形式:
      gs://{BOOK_DATA_BUCKET}/{book_keyword}.json に ["Chapter 1 - Item 1", ...] の配列として保存
    """
    book_keyword = (payload.get("book_keyword") or "").strip()
    if not book_keyword:
        return JSONResponse({"error": "book_keyword is required"}, status_code=400)

    try:
        items = _normalize_chapter_items(payload, book_keyword)
    except Exception as e:
        return JSONResponse({"error": f"chapter items error: {e}"}, status_code=400)

    overwrite = bool(payload.get("overwrite", False))
    bucket = gcs().bucket(BOOK_DATA_BUCKET)
    blob = bucket.blob(f"{book_keyword}.json")

    if blob.exists() and not overwrite:
        return JSONResponse({"error": "already exists. set overwrite=true to replace."}, status_code=409)

    try:
        blob.upload_from_string(json.dumps(items, ensure_ascii=False), content_type="application/json")
    except Exception as e:
        return JSONResponse({"error": f"save failed: {e}"}, status_code=500)

    return {"ok": True, "book_keyword": book_keyword, "gcs_uri": f"gs://{BOOK_DATA_BUCKET}/{book_keyword}.json", "count": len(items)}

@app.post("/acronyms/batch", dependencies=[Depends(verify_api_key)],
          response_model=AcronymCardsResponseModel)
def get_acronym_batch(payload: dict = Body(...)):
    """
    指定した用語の配列をまとめて返す
    body: { "terms": ["DNS","SMTP","DHCP"] }
    """
    terms = payload.get("terms") or []
    if not isinstance(terms, list):
        return JSONResponse({"error": "terms must be an array"}, status_code=400)
    _ac_load_from_gcs()
    out = []
    for t in terms:
        c = _AC_CACHE["terms"].get((t or "").upper())
        if c:
            out.append(c)
    return {"cards": out, "count": len(out), "etag": _AC_CACHE["etag"]}

@app.get("/acronyms/term/{term}",
         dependencies=[Depends(verify_api_key)],
         response_model=AcronymCardModel)
def get_acronym_card(term: str):
    """
    単語カード1件を返す（APIキーのみ、OAuth不要）
    例: GET /acronyms/term/DNS
    """
    card = _ac_get(term)
    if not card:
        raise HTTPException(status_code=404, detail="Term not found")
    resp = JSONResponse(card)
    resp.headers["Cache-Control"] = "public, max-age=3600"
    if _AC_CACHE["etag"]:
        resp.headers["ETag"] = _AC_CACHE["etag"]
    return resp

@app.get("/acronyms/{term}", include_in_schema=False,
         dependencies=[Depends(verify_api_key)])
def acronyms_compat(term: str):
    # 予約語はここでは扱わない（静的ルートへ回す）
    if term in {"session", "batch", "term"}:
        raise HTTPException(status_code=404, detail="Not Found")
    return RedirectResponse(url=f"/acronyms/term/{term}", status_code=307)

