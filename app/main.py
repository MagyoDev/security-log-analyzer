from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as api_router


BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="S.L.A — Security Log Analyzer",
    description="Local network traffic analyzer with FastAPI and Scapy",
    version="0.1.0",
)

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static",
)

app.include_router(api_router)


@app.get("/")
def read_index():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "app": "S.L.A — Security Log Analyzer",
        "version": "0.1.0",
    }