from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import check_login
from web.database import Cluster, Finding, Manifest, Scan, get_db

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")


@router.get("/")
async def dashboard(request: Request):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        total_scans     = db.query(Scan).count()
        total_manifests = db.query(Manifest).count()
        total_clusters  = db.query(Cluster).count()
        critical_open   = db.query(Finding).filter(Finding.severity == "CRITICAL").count()
        high_open       = db.query(Finding).filter(Finding.severity == "HIGH").count()

        recent_scans = (
            db.query(Scan)
            .order_by(Scan.id.desc())
            .limit(10)
            .all()
        )
        db.expunge_all()

    return templates.TemplateResponse(request, "dashboard.html", context={
        "user":           user,
        "total_scans":    total_scans,
        "total_manifests": total_manifests,
        "total_clusters": total_clusters,
        "critical_open":  critical_open,
        "high_open":      high_open,
        "recent_scans":   recent_scans,
    })
