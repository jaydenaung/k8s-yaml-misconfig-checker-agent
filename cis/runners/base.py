# Copyright 2026 Jayden Aung — Apache 2.0
"""
cis/runners/base.py — Abstract CheckRunner and RunnerContext.

A runner is a self-describing executor for one or more `tier` values. The
Orchestrator iterates over checks and asks each registered runner whether
it `can_run` a given check; the first match wins. New tiers (Tier 2 node
scanner, Tier 3 continuous, external integrations) plug in as new runners
without changes to the orchestrator or to the check schema.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from cis.result import CheckResult
from cis.schema import CheckDefinition


@dataclass
class RunnerContext:
    """
    Carries everything a runner needs to talk to a target cluster.

    For Tier 1, this is just the kubeconfig path; Tier 2 will extend this
    with a scanner-image reference, a target namespace, and an audit-log
    writer. We deliberately keep the surface area small so each tier owns
    its own concerns.
    """
    kubeconfig_path: Optional[str] = None
    cluster_name: Optional[str] = None


class CheckRunner(ABC):
    tier: str

    @abstractmethod
    def can_run(self, check: CheckDefinition) -> bool:
        """Return True if this runner can execute `check`."""

    @abstractmethod
    def run(self, check: CheckDefinition, ctx: RunnerContext) -> CheckResult:
        """Execute `check` and return a CheckResult. Must not raise."""
