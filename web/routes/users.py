from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import check_admin, hash_password
from web.database import User, get_db

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")


@router.get("/users")
async def users_list(request: Request):
    result = check_admin(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        users = db.query(User).order_by(User.created_at).all()
        db.expunge_all()

    return templates.TemplateResponse(request, "users.html", context={
        "user":    user,
        "users":   users,
        "error":   None,
    })


@router.post("/users/create")
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    is_admin: str = Form(default=""),
):
    result = check_admin(request)
    if isinstance(result, RedirectResponse):
        return result
    admin = result

    error = None
    if len(username.strip()) < 3:
        error = "Username must be at least 3 characters."
    elif len(password) < 8:
        error = "Password must be at least 8 characters."

    if not error:
        with get_db() as db:
            existing = db.query(User).filter(User.username == username.strip()).first()
            if existing:
                error = f"Username '{username}' is already taken."
            else:
                db.add(User(
                    username=username.strip(),
                    hashed_password=hash_password(password),
                    is_admin=bool(is_admin),
                    is_active=True,
                ))
                db.commit()

    if error:
        with get_db() as db:
            users = db.query(User).order_by(User.created_at).all()
            db.expunge_all()
        return templates.TemplateResponse(request, "users.html", context={
            "user":    admin,
            "users":   users,
            "error":   error,
        })

    return RedirectResponse("/users", status_code=302)


@router.post("/users/{user_id}/toggle")
async def toggle_user(request: Request, user_id: int):
    result = check_admin(request)
    if isinstance(result, RedirectResponse):
        return result
    admin = result

    with get_db() as db:
        target = db.query(User).filter(User.id == user_id).first()
        if target and target.id != admin.id:
            target.is_active = not target.is_active
            db.commit()

    return RedirectResponse("/users", status_code=302)
