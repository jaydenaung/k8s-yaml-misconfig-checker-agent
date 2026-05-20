# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/auth.py — Session helpers, password hashing, login guards
"""

from typing import Optional, Union

import bcrypt
from fastapi.responses import RedirectResponse
from starlette.requests import Request

from web.database import User, get_db


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def get_current_user(request: Request) -> Optional[User]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    with get_db() as db:
        user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
        if user:
            db.expunge(user)
        return user


def check_login(request: Request) -> Union[User, RedirectResponse]:
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return user


def check_admin(request: Request) -> Union[User, RedirectResponse]:
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if not user.is_admin:
        return RedirectResponse("/", status_code=302)
    return user
