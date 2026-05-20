# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/scheduler.py — APScheduler integration for scheduled cluster scans
"""

import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

from web.database import Cluster, Scan, engine, get_db
from web.scanner import run_scan

log = logging.getLogger(__name__)

scheduler = BackgroundScheduler(
    jobstores={"default": SQLAlchemyJobStore(engine=engine)},
    job_defaults={"coalesce": True, "max_instances": 1},
)


def _scheduled_cluster_scan(cluster_id: int, scan_mode: str) -> None:
    """Called by APScheduler — creates a Scan record and runs it."""
    with get_db() as db:
        cluster = db.query(Cluster).filter(Cluster.id == cluster_id).first()
        if not cluster:
            return
        scan = Scan(
            scan_type="cluster",
            target_id=cluster.id,
            target_name=cluster.name,
            scan_mode=scan_mode,
            triggered_by="scheduler",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

    run_scan(scan_id)


def upsert_cluster_schedule(cluster_id: int, cluster_name: str,
                             schedule_hours: int, scan_mode: str) -> None:
    """Add or replace the scheduled job for a cluster."""
    job_id = f"cluster_{cluster_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    if schedule_hours > 0:
        scheduler.add_job(
            _scheduled_cluster_scan,
            trigger="interval",
            hours=schedule_hours,
            id=job_id,
            name=f"Scan cluster: {cluster_name}",
            args=[cluster_id, scan_mode],
            replace_existing=True,
        )
        log.info("Scheduled cluster '%s' every %dh", cluster_name, schedule_hours)


def remove_cluster_schedule(cluster_id: int) -> None:
    job_id = f"cluster_{cluster_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


def restore_schedules() -> None:
    """Re-register schedules from DB on server startup (APScheduler SQLite jobstore
    persists jobs, but this ensures any clusters whose schedule changed while the
    server was down are still covered)."""
    with get_db() as db:
        clusters = db.query(Cluster).filter(Cluster.schedule_hours > 0).all()
        for c in clusters:
            upsert_cluster_schedule(c.id, c.name, c.schedule_hours, "static")
