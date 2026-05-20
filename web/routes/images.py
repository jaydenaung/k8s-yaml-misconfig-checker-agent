import json

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import check_login
from web.database import Image, Scan, get_db

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")


@router.get("/images")
async def images_list(request: Request):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        # Deduplicate by image_ref, show worst CVE counts seen
        rows = db.query(Image).order_by(Image.critical_cves.desc(), Image.scanned_at.desc()).all()
        seen: dict = {}
        for img in rows:
            if img.image_ref not in seen:
                seen[img.image_ref] = img
            else:
                existing = seen[img.image_ref]
                if img.critical_cves > existing.critical_cves:
                    seen[img.image_ref] = img
        images = list(seen.values())

        # Attach scan target name for context
        scan_map = {}
        scan_ids = {img.scan_id for img in rows}
        for sid in scan_ids:
            s = db.query(Scan).filter(Scan.id == sid).first()
            if s:
                scan_map[sid] = s.target_name
        db.expunge_all()

    details_map: dict = {}
    for img in images:
        if img.cve_details:
            try:
                details_map[img.image_ref] = json.loads(img.cve_details)
            except Exception:
                details_map[img.image_ref] = []

    return templates.TemplateResponse(request, "images.html", context={
        "user":        user,
        "images":      images,
        "scan_map":    scan_map,
        "details_map": details_map,
    })
