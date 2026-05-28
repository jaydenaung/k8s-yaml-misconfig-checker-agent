# Copyright 2026 Jayden Aung — Apache 2.0
"""
cis/runners/api_runner.py — Tier 1 runner. Pure read-only kubectl/API access.

Dispatches the check's audit.type to a parser, runs the parser, then applies
the check's expected.operator. Produces a CheckResult; never raises.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Optional

from cis.parsers import PARSERS, ParserError, ParserNotApplicable
from cis.parsers.base import ParserOutput
from cis.result import CheckResult, Status
from cis.runners.base import CheckRunner, RunnerContext
from cis.schema import CheckDefinition, Expected


class APIRunner(CheckRunner):
    tier = "api"

    def can_run(self, check: CheckDefinition) -> bool:
        return check.tier == "api" and check.audit.type in PARSERS

    def run(self, check: CheckDefinition, ctx: RunnerContext) -> CheckResult:
        started = time.perf_counter()
        parser = PARSERS[check.audit.type]
        try:
            output = parser(check.audit.params, ctx)
        except ParserNotApplicable as exc:
            return _result(
                check, Status.SKIP, started,
                expected=_expected_str(check.expected),
                actual=None,
                evidence=str(exc),
            )
        except ParserError as exc:
            return _result(
                check, Status.ERROR, started,
                expected=_expected_str(check.expected),
                actual=None,
                evidence=None,
                error=str(exc),
            )
        except Exception as exc:  # pragma: no cover — last-resort safety net
            return _result(
                check, Status.ERROR, started,
                expected=_expected_str(check.expected),
                actual=None,
                evidence=None,
                error=f"unhandled parser error: {exc}",
            )

        passed = _evaluate(check.expected, output.actual_value)
        status = Status.PASS if passed else Status.FAIL
        return _result(
            check, status, started,
            expected=_expected_str(check.expected),
            actual=output.actual_value,
            evidence=output.evidence_source,
        )


# ── Operator evaluation ──────────────────────────────────────────────────────

def _evaluate(expected: Expected, actual: Optional[str]) -> bool:
    op = expected.operator
    val = expected.value
    vals = expected.values

    if op == "exists":
        return actual is not None
    if op == "not_exists":
        return actual is None
    if actual is None:
        # All remaining operators require a concrete observed value.
        return False
    if op == "equals":
        return actual == val
    if op == "not_equals":
        return actual != val
    if op == "in":
        return actual in (vals or [])
    if op == "regex":
        return bool(re.search(val or "", actual))
    if op == "gte":
        return _as_int(actual, default=None) is not None and int(actual) >= int(val)
    if op == "lte":
        return _as_int(actual, default=None) is not None and int(actual) <= int(val)
    # Unknown operator: fail closed, never silently pass.
    return False


def _as_int(s: Optional[str], default):
    try:
        return int(s)
    except (TypeError, ValueError):
        return default


def _expected_str(e: Expected) -> str:
    if e.values is not None:
        return f"{e.operator} {e.values}"
    if e.value is not None:
        return f"{e.operator} {e.value}"
    return e.operator


def _result(
    check: CheckDefinition,
    status: Status,
    started: float,
    expected: Optional[str],
    actual: Optional[str],
    evidence: Optional[str],
    error: Optional[str] = None,
) -> CheckResult:
    duration_ms = int((time.perf_counter() - started) * 1000)
    return CheckResult(
        control_id=check.id,
        status=status,
        title=check.title,
        section=check.section,
        profile=check.profile,
        level=check.level,
        scored=check.scored,
        severity=check.severity if status == Status.FAIL else None,
        expected_value=expected,
        actual_value=actual,
        evidence_source=evidence,
        remediation=check.remediation,
        references=check.references,
        duration_ms=duration_ms,
        error=error,
        checked_at=datetime.utcnow(),
    )
