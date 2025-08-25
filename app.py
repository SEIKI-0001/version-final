# ===== Standard Library =====
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
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials as UserCredentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.cloud import storage

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

# スコープ（当面 Calendar 未使用ならコメントアウト可）
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/calendar.events",  # ← 未使用なら外してもOK
]

EXEMPT_PATHS = {"/", "/health", "/oauth/start", "/oauth/callback", "/auth/status"}
STATE_TTL = 10 * 60  # OAuth state の有効期間（秒）
DAY_ABBR = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

# ===== FastAPI =====
app = FastAPI()


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
    client = storage.Client()
    return client.bucket(TOKEN_BUCKET)

def _token_blob_path(user_id: str) -> str:
    safe = base64.urlsafe_b64encode(user_id.encode()).decode().rstrip("=")
    return f"tokens/{safe}.json"

def save_refresh_token(user_id: str, refresh_token: str):
    blob = _token_bucket().blob(_token_blob_path(user_id))
    data = {"user_id": user_id, "refresh_token": refresh_token, "updated_at": int(time.time())}
    blob.upload_from_string(json.dumps(data), content_type="application/json")

def load_refresh_token(user_id: str) -> Optional[str]:
    blob = _token_bucket().blob(_token_blob_path(user_id))
    if not blob.exists():
        return None
    data = json.loads(blob.download_as_text())
    return data.get("refresh_token")


# ===== OAuth Flow =====
def oauth_redirect_uri() -> str:
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
    auth_url, _ = flow.authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent", state=signed_state(user_id)
    )
    return RedirectResponse(auth_url, status_code=302)

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
    return {"user_id": user_id, "authorized": bool(load_refresh_token(user_id))}

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

def expand_chapter_items(counts: List[int]) -> List[str]:
    items = []
    for idx, c in enumerate(counts):
        for j in range(1, c + 1):
            items.append(f"Chapter {idx+1} - Item {j}")
    return items

def load_chapter_data_from_gcs(book_filename: str) -> List[str]:
    client = storage.Client()
    bucket = client.bucket(BOOK_DATA_BUCKET)
    blob = bucket.blob(book_filename)
    if not blob.exists():
        raise FileNotFoundError(f"chapter data not found: gs://{BOOK_DATA_BUCKET}/{book_filename}")
    try:
        return json.loads(blob.download_as_text())
    except Exception as e:
        raise ValueError(f"invalid chapter data: {e}")

def calculate_available_time(user: UserSetting, date: datetime) -> int:
    if is_rest_day(date, user.rest_days):
        return 0
    return user.weekend_minutes if is_weekend(date) else user.weekday_minutes

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

    def run_phase2(self):
        if not self.is_short:
            self.step6_refresh_days()
        self.step7_past_exam_plan()
        self.step8_summarize_tasks()
        self.step9_merge_plan()


def generate_study_plan(data: dict, user_id: str) -> Tuple[pd.DataFrame, UserSetting]:
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
    chapter_items_list = data.get("chapter_items_list")
    if chapter_items_list:
        if all(isinstance(x, int) for x in chapter_items_list):
            chapter_items_list = expand_chapter_items(chapter_items_list)
    else:
        chapter_items_list = load_chapter_data_from_gcs(f"{user.book_keyword}.json")

    planner = StudyPlanner(user, chapter_items_list)
    planner.run_phase1()
    planner.run_phase2()
    return planner.plan_df, user

# ===== Sheets/GCS ヘルパー =====

def backup_sheet_to_gcs(user_id: str, spreadsheet_id: str, values: List[List[str]]) -> str:
    """
    現在のシート内容を CSV にして BACKUP_BUCKET に保存。
    パス: gpts-plans/{user_id}/backup/{YYYYmmdd_HHMMSS}.csv
    """
    client = storage.Client()
    bucket = client.bucket(BACKUP_BUCKET)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = f"gpts-plans/{user_id}/backup/{ts}.csv"
    sio = io.StringIO()
    writer = csv.writer(sio)
    for row in values:
        writer.writerow(row)
    blob = bucket.blob(path)
    blob.upload_from_string(sio.getvalue(), content_type="text/csv")
    return f"gs://{BACKUP_BUCKET}/{path}"


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


def _safe_int_from_wbs(wbs: str) -> Optional[int]:
    try:
        if isinstance(wbs, str) and wbs.startswith("wbs"):
            return int(wbs[3:])
    except Exception:
        pass
    return None


def _next_wbs_id_from_column_a(a_values: List[List[str]]) -> str:
    """
    A2:A の wbs から最大値+1 を採番。存在しなければ wbs0。
    """
    max_idx = -1
    for row in a_values:
        if not row:
            continue
        n = _safe_int_from_wbs((row[0] or "").strip())
        if n is not None and n > max_idx:
            max_idx = n
    return f"wbs{max_idx + 1}"


def _read_all_values(service, spreadsheet_id: str) -> Tuple[str, List[List[str]]]:
    meta = service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
    sheet_title = meta["sheets"][0]["properties"]["title"]
    res = service.spreadsheets().values().get(
        spreadsheetId=spreadsheet_id, range=f"{sheet_title}!A1:F10000"
    ).execute()
    return sheet_title, res.get("values", [])

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


# ===== Endpoints =====
@app.post("/generate", dependencies=[Depends(verify_api_key)])
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
            access_type="offline", include_granted_scopes="true", prompt="consent", state=signed_state(user_id)
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
            access_type="offline", include_granted_scopes="true", prompt="consent", state=signed_state(user_id)
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Authorization expired. Please re-authorize."
        }, status_code=200)
    except Exception as e:
        return JSONResponse({"error": f"Sheets error: {e}"}, status_code=500)

    spreadsheet_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}"

    # マッピング保存（失敗しても続行）
    try:
        mapping = load_user_sheet_map()
        mapping[user_id] = {"spreadsheet_id": spreadsheet_id, "spreadsheet_url": spreadsheet_url}
        save_user_sheet_map(mapping)
    except Exception as e:
        print("[warn] save mapping failed:", e)

    return {
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": spreadsheet_url,
        "plan": plan_df.to_dict(orient="records")
    }


def get_user_spreadsheet_id(user_id: str) -> Optional[str]:
    mapping = load_user_sheet_map()
    if not mapping or user_id not in mapping:
        return None
    return mapping[user_id].get("spreadsheet_id")

@app.post("/get_tasks", dependencies=[Depends(verify_api_key)])
def get_tasks(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
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
            spreadsheetId=spreadsheet_id, range=f"{sheet_title}!A1:F10000"
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read sheet: {e}"}, status_code=500)

    values = res.get("values", [])
    if not values or len(values) < 2:
        return {"tasks": []}

    headers = values[0]
    rows = values[1:]
    tasks = [
        {headers[i]: (row[i] if i < len(row) else "") for i in range(len(headers))}
        for row in rows
        if any((c or "").strip() for c in row)
    ]
    return {"tasks": tasks}

# === New: Backup-only & Regenerate endpoints ===

@app.post("/backup", dependencies=[Depends(verify_api_key)])
def backup_only(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)

    svc = get_user_sheets_service(user_id)
    if svc is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    try:
        _, values = _read_all_values(svc, spreadsheet_id)
        if not values:
            return JSONResponse({"error": "sheet has no data"}, status_code=400)
        gs_uri = backup_sheet_to_gcs(user_id, spreadsheet_id, values)
        return {"ok": True, "backup_uri": gs_uri, "rows": len(values)-1}
    except Exception as e:
        return JSONResponse({"error": f"backup failed: {e}"}, status_code=500)


@app.post("/regenerate", dependencies=[Depends(verify_api_key)])
def regenerate_and_overwrite(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)

    # 認可
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

    # 新プラン生成
    try:
        plan_df, user = generate_study_plan(payload, user_id)
    except Exception as e:
        return JSONResponse({"error": f"plan generation failed: {e}"}, status_code=400)

    svc = get_user_sheets_service(user_id)
    if svc is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    # バックアップ → 上書き
    try:
        _, values = _read_all_values(svc, spreadsheet_id)
        backup_uri = None
        if values:
            backup_uri = backup_sheet_to_gcs(user.user_id, spreadsheet_id, values)
        write_tasks_to_sheet(spreadsheet_id, plan_df, user.user_id)
    except Exception as e:
        return JSONResponse({"error": f"Sheets error: {e}"}, status_code=500)

    spreadsheet_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}"
    return {
        "ok": True,
        "backup_uri": backup_uri,
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": spreadsheet_url,
        "plan_preview": plan_df.head(5).to_dict(orient="records")
    }
