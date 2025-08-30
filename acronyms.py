# acronyms.py
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from google.cloud import storage
import os, json, time, random
from security import verify_api_key  # 既存のAPIキー検証を流用

router = APIRouter(
    prefix="/acronyms",
    tags=["acronyms"],
    dependencies=[Depends(verify_api_key)]  # ← APIキーのみ（OAuthなし）
)

# ===== 設定（環境変数） =====
_CONTENT_BUCKET = os.getenv("CONTENT_BUCKET", "maru-content")
_ACRONYM_PATH   = os.getenv("ACRONYM_PATH",   "acronyms/itpass_core.json")
_REFRESH_SEC    = int(os.getenv("ACRONYM_REFRESH_SEC", "3600"))  # デフォ1h

# ===== 簡易キャッシュ =====
_CACHE = {"terms": {}, "last": 0, "etag": None}

def _load_from_gcs(force: bool = False):
    now = time.time()
    if not force and (now - _CACHE["last"] < _REFRESH_SEC) and _CACHE["terms"]:
        return
    cli = storage.Client()
    blob = cli.bucket(_CONTENT_BUCKET).blob(_ACRONYM_PATH)

    # ETagで変更検知（変更なければスキップ）
    blob.reload()  # メタ取得
    etag = blob.etag
    if not force and _CACHE["etag"] and etag == _CACHE["etag"]:
        _CACHE["last"] = now
        return

    data = blob.download_as_text()
    obj = json.loads(data)

    # 正規化：キーは大文字化、valueはAcronymCard
    terms = {}
    for k, card in obj.items():
        key = (k or "").upper()
        if not key:
            continue
        terms[key] = card

    _CACHE["terms"] = terms
    _CACHE["last"]  = now
    _CACHE["etag"]  = etag

def _get_card(term: str):
    _load_from_gcs()
    return _CACHE["terms"].get((term or "").upper())

@router.get("/{term}")
def get_card(term: str):
    card = _get_card(term)
    if not card:
        raise HTTPException(404, "Term not found")
    # 軽いキャッシュ制御（任意）
    resp = JSONResponse(card)
    resp.headers["Cache-Control"] = "public, max-age=3600"
    if _CACHE["etag"]:
        resp.headers["ETag"] = _CACHE["etag"]
    return resp

@router.post("/batch")
def get_batch(body: dict):
    terms = body.get("terms") or []
    if not isinstance(terms, list):
        raise HTTPException(400, "terms must be an array")
    _load_from_gcs()
    out = []
    for t in terms:
        c = _CACHE["terms"].get((t or "").upper())
        if c:
            out.append(c)
    return {"cards": out, "count": len(out), "etag": _CACHE["etag"]}

@router.get("/session")
def get_session(count: int = Query(10, ge=1, le=30), shuffle: bool = True):
    _load_from_gcs()
    items = list(_CACHE["terms"].values())
    if shuffle:
        random.shuffle(items)
    picked = items[:count]
    return {"cards": picked, "count": len(picked), "etag": _CACHE["etag"]}
