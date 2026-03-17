from __future__ import annotations

from fastapi import FastAPI

from backend.api.routes import router

app = FastAPI(title="PyMess Secure Backend", version="0.2.0-supabase")
app.include_router(router, prefix="/api")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
