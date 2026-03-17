from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import Response
from starlette.middleware.gzip import GZipMiddleware

from backend.api.routes import router
from backend.config import settings

app = FastAPI(title="PyMess Secure Backend", version="0.4.0-supabase-prod")
app.include_router(router, prefix="/api")
app.add_middleware(GZipMiddleware, minimum_size=settings.gzip_min_size)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
