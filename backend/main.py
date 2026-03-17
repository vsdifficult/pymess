from __future__ import annotations

from fastapi import FastAPI

from backend.api.routes import router
from backend.database import Base, engine

app = FastAPI(title="PyMess Secure Backend", version="0.1.0")
app.include_router(router, prefix="/api")


@app.on_event("startup")
async def startup() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
