import shutil
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import check_login
from web.database import Finding, Manifest, Scan, get_db
from web.scanner import run_scan

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")
UPLOAD_DIR = Path("data/uploads/manifests")


@router.get("/manifests")
async def manifests_list(request: Request):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        manifests = db.query(Manifest).order_by(Manifest.uploaded_at.desc()).all()
        # Attach latest scan to each manifest
        manifest_data = []
        for m in manifests:
            latest = (
                db.query(Scan)
                .filter(Scan.scan_type == "manifest", Scan.target_id == m.id)
                .order_by(Scan.id.desc())
                .first()
            )
            manifest_data.append({"manifest": m, "latest_scan": latest})
        db.expunge_all()

    return templates.TemplateResponse(request, "manifests.html", context={
        "user":          user,
        "manifest_data": manifest_data,
    })


@router.post("/manifests/upload")
async def upload_manifest(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    scan_mode: str = Form(...),
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    if not file.filename.endswith((".yaml", ".yml")):
        return RedirectResponse("/manifests?error=not_yaml", status_code=302)

    with get_db() as db:
        manifest = Manifest(
            filename=file.filename,
            file_path="",
            uploaded_by=user.id,
            uploaded_by_name=user.username,
        )
        db.add(manifest)
        db.commit()
        db.refresh(manifest)

        dest = UPLOAD_DIR / f"{manifest.id}_{file.filename}"
        with open(dest, "wb") as f:
            shutil.copyfileobj(file.file, f)

        manifest.file_path = str(dest)
        db.commit()

        scan = Scan(
            scan_type="manifest",
            target_id=manifest.id,
            target_name=file.filename,
            scan_mode=scan_mode,
            triggered_by=user.username,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
        manifest_id = manifest.id

    background_tasks.add_task(run_scan, scan_id)
    return RedirectResponse(f"/manifests/{manifest_id}", status_code=302)


@router.get("/manifests/{manifest_id}")
async def manifest_detail(request: Request, manifest_id: int):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        manifest = db.query(Manifest).filter(Manifest.id == manifest_id).first()
        if not manifest:
            return RedirectResponse("/manifests", status_code=302)

        scans = (
            db.query(Scan)
            .filter(Scan.scan_type == "manifest", Scan.target_id == manifest_id)
            .order_by(Scan.id.desc())
            .all()
        )
        latest_scan = scans[0] if scans else None
        findings = []
        if latest_scan and latest_scan.status == "done":
            findings = (
                db.query(Finding)
                .filter(Finding.scan_id == latest_scan.id)
                .order_by(Finding.severity)
                .all()
            )
        db.expunge_all()

    return templates.TemplateResponse(request, "manifest_detail.html", context={
        "user":        user,
        "manifest":    manifest,
        "scans":       scans,
        "latest_scan": latest_scan,
        "findings":    findings,
    })


@router.post("/manifests/{manifest_id}/scan")
async def rescan_manifest(
    request: Request,
    manifest_id: int,
    background_tasks: BackgroundTasks,
    scan_mode: str = Form(...),
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        manifest = db.query(Manifest).filter(Manifest.id == manifest_id).first()
        if not manifest:
            return RedirectResponse("/manifests", status_code=302)
        scan = Scan(
            scan_type="manifest",
            target_id=manifest.id,
            target_name=manifest.filename,
            scan_mode=scan_mode,
            triggered_by=user.username,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

    background_tasks.add_task(run_scan, scan_id)
    return RedirectResponse(f"/manifests/{manifest_id}", status_code=302)
