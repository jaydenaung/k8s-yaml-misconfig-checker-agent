# Copyright 2026 Jayden Aung — Apache 2.0
"""
cis/result.py — CheckResult dataclass and Status enum.

The result schema is deliberately distinct from the vulnerability `findings`
schema: compliance results are evidence-bearing PASS/FAIL/SKIP/MANUAL/ERROR
records with structured expected vs. actual fields.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"        # check not applicable in this environment
    MANUAL = "MANUAL"    # requires human review (no machine pass/fail)
    ERROR = "ERROR"      # runner failed unexpectedly


@dataclass
class CheckResult:
    control_id: str
    status: Status
    title: str
    section: str
    profile: str
    level: int
    scored: bool
    severity: Optional[str] = None
    expected_value: Optional[str] = None
    actual_value: Optional[str] = None
    evidence_source: Optional[str] = None
    remediation: Optional[str] = None
    references: Dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    error: Optional[str] = None
    checked_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, Status) else self.status
        if self.checked_at is not None:
            d["checked_at"] = self.checked_at.isoformat()
        return d


def score(results: list) -> int:
    """
    Compute a 0..100 compliance score.

    Scored checks count; MANUAL and SKIP do not. ERROR is treated as FAIL
    so a broken runner cannot silently produce a 100% score.
    """
    scored_results = [
        r for r in results
        if r.scored and r.status not in (Status.MANUAL, Status.SKIP)
    ]
    if not scored_results:
        return 0
    passed = sum(1 for r in scored_results if r.status == Status.PASS)
    return round(100 * passed / len(scored_results))
