# Copyright 2026 Jayden Aung — Apache 2.0
"""
server.py — KubeSentinel web server

Usage:
    python server.py                        # default: 0.0.0.0:8000
    python server.py --host 0.0.0.0 --port 8080
    python server.py --host 127.0.0.1      # local only
"""

import argparse
import os
import secrets
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from web.database import has_users, init_db
from web.routes import api, auth, clusters, dashboard, images, manifests, scans, setup, users
from web.scheduler import restore_schedules, scheduler


def _get_secret_key() -> str:
    key_file = Path("data/.secret_key")
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    key_file.chmod(0o600)
    return key


app = FastAPI(title="KubeSentinel", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=_get_secret_key(), session_cookie="ks_session")

app.include_router(setup.router)
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(manifests.router)
app.include_router(clusters.router)
app.include_router(images.router)
app.include_router(scans.router)
app.include_router(users.router)
app.include_router(api.router)


@app.middleware("http")
async def setup_guard(request: Request, call_next):
    """Redirect everything except /setup to /setup when no users exist."""
    if not request.url.path.startswith("/setup") and not has_users():
        return RedirectResponse("/setup")
    return await call_next(request)


@app.on_event("startup")
async def startup():
    init_db()
    scheduler.start()
    restore_schedules()


@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown(wait=False)


if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="KubeSentinel web server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    args = parser.parse_args()

    print(f"\n  🛡  KubeSentinel — AI-powered Kubernetes Security")
    print(f"  Dashboard: http://{args.host}:{args.port}")
    print(f"  Network:   http://<your-ip>:{args.port}\n")

    uvicorn.run("server:app", host=args.host, port=args.port, reload=False)
