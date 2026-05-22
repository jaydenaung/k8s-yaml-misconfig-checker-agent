from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import check_login
from web.database import Finding, Scan, get_db
from web.scanner import run_patch_generation

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@router.get("/scans/{scan_id}")
async def scan_detail(request: Request, scan_id: int):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return RedirectResponse("/", status_code=302)
        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .all()
        )
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity or "INFO", 99))
        db.expunge_all()

    return templates.TemplateResponse(request, "scan_detail.html", context={
        "user":     user,
        "scan":     scan,
        "findings": findings,
    })


@router.post("/scans/{scan_id}/patches")
async def generate_patches(
    request: Request,
    scan_id: int,
    background_tasks: BackgroundTasks,
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result

    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.status != "done":
            return RedirectResponse(f"/scans/{scan_id}", status_code=302)
        if scan.patches_status in ("generating", "done"):
            return RedirectResponse(f"/scans/{scan_id}", status_code=302)

    background_tasks.add_task(run_patch_generation, scan_id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=302)
