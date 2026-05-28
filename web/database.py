# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/database.py — SQLAlchemy models and DB initialisation
"""

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from sqlalchemy import (Boolean, Column, DateTime, Integer, String, Text,
                        create_engine, text)
from sqlalchemy.orm import declarative_base, sessionmaker

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
(DATA_DIR / "uploads" / "manifests").mkdir(parents=True, exist_ok=True)
(DATA_DIR / "kubeconfigs").mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DATA_DIR}/kubesentinel.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id               = Column(Integer, primary_key=True, index=True)
    username         = Column(String(64), unique=True, nullable=False)
    email            = Column(String(128), unique=True, nullable=True)
    hashed_password  = Column(String(256), nullable=False)
    is_admin         = Column(Boolean, default=False)
    is_active        = Column(Boolean, default=True)
    created_at       = Column(DateTime, default=datetime.utcnow)


class Manifest(Base):
    __tablename__ = "manifests"
    id               = Column(Integer, primary_key=True, index=True)
    filename         = Column(String(256), nullable=False)
    file_path        = Column(String(512), nullable=False)
    uploaded_by      = Column(Integer, nullable=True)
    uploaded_by_name = Column(String(64), nullable=True)
    uploaded_at      = Column(DateTime, default=datetime.utcnow)


class Cluster(Base):
    __tablename__ = "clusters"
    id               = Column(Integer, primary_key=True, index=True)
    name             = Column(String(128), unique=True, nullable=False)
    kubeconfig_path  = Column(String(512), nullable=False)
    added_by         = Column(Integer, nullable=True)
    added_by_name    = Column(String(64), nullable=True)
    added_at         = Column(DateTime, default=datetime.utcnow)
    schedule_hours   = Column(Integer, default=0)   # 0 = off
    last_scanned_at  = Column(DateTime, nullable=True)


class Scan(Base):
    __tablename__ = "scans"
    id             = Column(Integer, primary_key=True, index=True)
    scan_type      = Column(String(16), nullable=False)   # manifest | cluster
    target_id      = Column(Integer, nullable=False)
    target_name    = Column(String(256), nullable=True)   # filename or cluster name
    scan_mode      = Column(String(16), nullable=False)   # ai | static | cis
    status         = Column(String(16), default="queued") # queued|running|done|failed
    started_at     = Column(DateTime, nullable=True)
    completed_at   = Column(DateTime, nullable=True)
    critical_count = Column(Integer, default=0)
    high_count     = Column(Integer, default=0)
    medium_count   = Column(Integer, default=0)
    low_count      = Column(Integer, default=0)
    info_count     = Column(Integer, default=0)
    triggered_by    = Column(String(64), nullable=True)    # username or "scheduler"
    error_message   = Column(Text, nullable=True)
    patches_status  = Column(String(16), default="none")  # none | generating | done | failed
    # Compliance scan fields (null for vulnerability scans).
    framework       = Column(String(64), nullable=True)    # e.g. "cis-kubernetes-1.9"
    compliance_score = Column(Integer, nullable=True)      # 0-100, cached for fast list rendering
    pass_count       = Column(Integer, default=0)
    fail_count       = Column(Integer, default=0)
    skip_count       = Column(Integer, default=0)
    manual_count     = Column(Integer, default=0)


class Finding(Base):
    __tablename__ = "findings"
    id              = Column(Integer, primary_key=True, index=True)
    scan_id         = Column(Integer, nullable=False, index=True)
    check_id        = Column(String(32), nullable=True)
    severity        = Column(String(16), nullable=True)
    source          = Column(String(16), nullable=True)   # static | claude-ai
    context         = Column(String(256), nullable=True)
    title           = Column(String(256), nullable=True)
    detail          = Column(Text, nullable=True)
    remediation     = Column(Text, nullable=True)
    resource_path   = Column(String(256), nullable=True)
    attack_scenario   = Column(Text, nullable=True)
    telco_relevance   = Column(Text, nullable=True)
    suggested_patch   = Column(Text, nullable=True)
    patch_explanation = Column(Text, nullable=True)


class ComplianceResult(Base):
    """
    One row per (scan, CIS control) — the evidence-bearing compliance record.

    Deliberately separate from `findings`: vulnerability findings and compliance
    results have different status semantics (severity vs PASS/FAIL/SKIP/MANUAL),
    different evidence shapes, and different downstream access patterns
    (severity rollup vs per-control time series).
    """
    __tablename__ = "compliance_results"
    id              = Column(Integer, primary_key=True, index=True)
    scan_id         = Column(Integer, nullable=False, index=True)
    control_id      = Column(String(32), nullable=False, index=True)
    title           = Column(String(512), nullable=True)
    section         = Column(String(64), nullable=True)
    profile         = Column(String(32), nullable=True)   # control-plane | worker | policies
    level           = Column(Integer, default=1)
    scored          = Column(Boolean, default=True)
    status          = Column(String(16), nullable=False)  # PASS|FAIL|SKIP|MANUAL|ERROR
    severity        = Column(String(16), nullable=True)
    expected_value  = Column(String(256), nullable=True)
    actual_value    = Column(Text, nullable=True)
    evidence_source = Column(Text, nullable=True)
    remediation     = Column(Text, nullable=True)
    references      = Column(Text, nullable=True)         # JSON
    duration_ms     = Column(Integer, default=0)
    error_message   = Column(Text, nullable=True)
    checked_at      = Column(DateTime, default=datetime.utcnow)


class Image(Base):
    __tablename__ = "images"
    id           = Column(Integer, primary_key=True, index=True)
    scan_id      = Column(Integer, nullable=False, index=True)
    image_ref    = Column(String(512), nullable=False)
    critical_cves = Column(Integer, default=0)
    high_cves    = Column(Integer, default=0)
    medium_cves  = Column(Integer, default=0)
    low_cves     = Column(Integer, default=0)
    total_cves   = Column(Integer, default=0)
    cve_details  = Column(Text, nullable=True)   # JSON
    scanned_at   = Column(DateTime, default=datetime.utcnow)


def _migrate():
    """Add columns introduced after the initial schema — safe to run on every startup."""
    new_columns = [
        ("findings", "suggested_patch",   "TEXT"),
        ("findings", "patch_explanation", "TEXT"),
        ("scans",    "patches_status",    "TEXT DEFAULT 'none'"),
        ("scans",    "framework",         "TEXT"),
        ("scans",    "compliance_score",  "INTEGER"),
        ("scans",    "pass_count",        "INTEGER DEFAULT 0"),
        ("scans",    "fail_count",        "INTEGER DEFAULT 0"),
        ("scans",    "skip_count",        "INTEGER DEFAULT 0"),
        ("scans",    "manual_count",      "INTEGER DEFAULT 0"),
    ]
    with engine.connect() as conn:
        for table, col, coltype in new_columns:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}"))
                conn.commit()
            except Exception:
                pass  # column already exists


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate()


@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def has_users() -> bool:
    with get_db() as db:
        return db.query(User).count() > 0
