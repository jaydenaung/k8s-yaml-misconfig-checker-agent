# Copyright 2026 Jayden Aung — Apache 2.0
"""
cis/runners/orchestrator.py — Dispatch checks to runners, aggregate results.

The orchestrator is dumb on purpose: it owns iteration, error containment,
and aggregation, but not check semantics. Adding Tier 2 (node scanner) means
registering another runner here; the orchestrator doesn't change.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from cis.result import CheckResult, Status
from cis.runners.base import CheckRunner, RunnerContext
from cis.schema import Benchmark, CheckDefinition


class Orchestrator:
    def __init__(self, runners: List[CheckRunner]):
        if not runners:
            raise ValueError("Orchestrator requires at least one runner")
        self.runners = runners

    def _pick_runner(self, check: CheckDefinition):
        for runner in self.runners:
            if runner.can_run(check):
                return runner
        return None

    def run_benchmark(
        self,
        benchmark: Benchmark,
        ctx: RunnerContext,
        profile: str = None,
    ) -> List[CheckResult]:
        checks = benchmark.by_profile(profile) if profile else benchmark.checks
        return [self.run_check(c, ctx) for c in checks]

    def run_check(self, check: CheckDefinition, ctx: RunnerContext) -> CheckResult:
        runner = self._pick_runner(check)
        if runner is None:
            return CheckResult(
                control_id=check.id,
                status=Status.SKIP,
                title=check.title,
                section=check.section,
                profile=check.profile,
                level=check.level,
                scored=check.scored,
                severity=None,
                expected_value=None,
                actual_value=None,
                evidence_source=(
                    f"No registered runner can execute "
                    f"tier={check.tier} type={check.audit.type} "
                    "(likely needs Tier 2 — Trusted Scan Mode)."
                ),
                remediation=check.remediation,
                references=check.references,
                duration_ms=0,
                error=None,
                checked_at=datetime.utcnow(),
            )
        return runner.run(check, ctx)
