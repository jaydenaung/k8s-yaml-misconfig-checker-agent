from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import get_current_user, verify_password
from web.database import User, get_db, has_users

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")


@router.get("/login")
async def login_page(request: Request):
    if not has_users():
        return RedirectResponse("/setup", status_code=302)
    if get_current_user(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", context={"error": None})


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    with get_db() as db:
        user = db.query(User).filter(
            User.username == username.strip(),
            User.is_active == True,
        ).first()

    error = None
    if not user or not verify_password(password, user.hashed_password):
        error = "Invalid username or password."

    if error:
        return templates.TemplateResponse(request, "login.html", context={"error": error})

    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=302)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)
