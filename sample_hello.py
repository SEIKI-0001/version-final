from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello, World! from FastAPI"}

@app.get("/healthz")
def healthz():
    return {"ok": True}

class GenReq(BaseModel):
    user_id: str | None = None
    message: str | None = None

@app.post("/generate")
def generate(req: GenReq):
    return {"echo": req.model_dump(), "ok": True}
