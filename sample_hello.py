import os
from typing import List, Optional, Union, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI()

# ===== 日付ユーティリティ =====
DAY_ABBR = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
def weekday_abbr(d: datetime) -> str: return DAY_ABBR[d.weekday()]
def is_weekend(d: datetime) -> bool: return d.weekday() >= 5
def next_day(d: datetime) -> datetime: return d + timedelta(days=1)

# ===== 設定/データモデル =====
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
        return weekday_abbr(self.Date)

MIN1, MIN2, MIN3 = 10, 7, 5

def calculate_available_time(user: UserSetting, date: datetime) -> int:
    if weekday_abbr(date) in set(user.rest_days):
        return 0
    if is_weekend(date):
        return user.weekend_minutes
    return user.weekday_minutes

# ===== プランナー本体（Sheets 連携なしの純粋計算版）=====
class StudyPlanner:
    def __init__(self, user: UserSetting, chapter_items_list: List[str]):
        self.user = user
        self.chapter_items_list = chapter_items_list[:]
        self.tasks: List[Task] = []
        self.wbs_counter = 0
        self.last_study_date: Optional[datetime] = None
        self.first_round_tasks: List[str] = []
        self.is_short = (self.user.target_exam - self.user.start_date).days <= 31

    def add_task(self, name: str, date: datetime, minutes: int):
        self.tasks.append(Task(f"wbs{self.wbs_counter}", name, date, minutes))
        self.wbs_counter += 1
        if self.last_study_date is None or date > self.last_study_date:
            self.last_study_date = date

    def allocate_tasks(self, tasks: List[Tuple[str, int]], start_date: datetime):
        current_date = start_date
        while tasks and current_date <= self.user.target_exam:
            while calculate_available_time(self.user, current_date) == 0:
                current_date = next_day(current_date)
                if current_date > self.user.target_exam:
                    break
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
            while tasks and current_date <= cutoff_date:
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
            if not self.is_short and start_date <= cutoff:
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

    def build_plan_records(self):
        return [{
            "WBS": t.WBS,
            "Task Name": t.Task_Name,
            "Date": t.Date.strftime('%Y-%m-%d'),
            "Day": t.Day,
            "Duration": t.Duration,
            "Status": t.Status
        } for t in sorted(self.tasks, key=lambda x: x.Date)]

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

def expand_chapter_items(counts: List[int]) -> List[str]:
    items = []
    for idx, c in enumerate(counts):
        for j in range(1, c + 1):
            items.append(f"Chapter {idx + 1} - Item {j}")
    return items

def generate_study_plan(data: dict, user_id: str):
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
        # GCS 連携なし版の簡易デフォルト
        chapter_items_list = [f"Chapter {i}" for i in range(1, 21)]
    planner = StudyPlanner(user, chapter_items_list)
    planner.run_phase1()
    planner.run_phase2()
    return planner.build_plan_records(), {
        "user_id": user.user_id,
        "start_date": user.start_date.strftime("%Y-%m-%d"),
        "target_exam_date": user.target_exam.strftime("%Y-%m-%d"),
        "is_short": planner.is_short,
    }

# ===== FastAPI ルート =====
@app.get("/")
def root():
    return {"message": "Hello, World! from FastAPI"}

@app.get("/healthz")
def healthz():
    return {"ok": True}

class GenerateIn(BaseModel):
    user_id: str = Field(..., description="ユーザーID（メールなど）")
    target_exam_date: str = Field(..., description="YYYY-MM-DD")
    start_date: str = Field(..., description="YYYY-MM-DD")
    weekday_minutes: int = 60
    weekend_minutes: int = 120
    rest_days: List[str] = ["Wed"]
    weekday_start: str = "20:00"
    weekend_start: str = "13:00"
    book_keyword: str
    # 章構成: ["Chapter 1 - Item 1", ...] か [3,4,5] の形式（後者は expand）
    chapter_items_list: Optional[List[Union[str, int]]] = None

@app.post("/generate")
def generate_endpoint(payload: GenerateIn):
    try:
        plan, meta = generate_study_plan(payload.model_dump(), payload.user_id)
        return {
            "requires_auth": False,          # ← Sheets 連携なし
            "spreadsheet_id": None,          # ← 後で実装
            "spreadsheet_url": None,         # ← 後で実装
            "plan": plan,
            "meta": meta
        }
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"missing field: {e}")
    except Exception as e:
        # 予期しないエラーは 400 で返す（Cloud Run 上で分かりやすくするため）
        raise HTTPException(status_code=400, detail=str(e))
