from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from web.auth import get_current_user
from web.database import Scan, get_db

router = APIRouter(prefix="/api")


@router.get("/scans/{scan_id}/status")
async def scan_status(request: Request, scan_id: int):
    if not get_current_user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse({
            "status":                scan.status,
            "patches_status":        scan.patches_status or "none",
            "enrichment_status":     scan.enrichment_status or "none",
            "critical_count":        scan.critical_count,
            "high_count":            scan.high_count,
            "medium_count":          scan.medium_count,
            "low_count":             scan.low_count,
            "error_message":         scan.error_message,
            "input_tokens":          scan.input_tokens or 0,
            "output_tokens":         scan.output_tokens or 0,
            "cache_creation_tokens": scan.cache_creation_tokens or 0,
            "cache_read_tokens":     scan.cache_read_tokens or 0,
            "estimated_cost_usd":    round(scan.estimated_cost_usd or 0.0, 6),
        })
