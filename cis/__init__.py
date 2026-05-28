# Copyright 2026 Jayden Aung — Apache 2.0
"""
KubeSentinel CIS Benchmark module.

Declarative, multi-tier compliance scanning for Kubernetes against the
CIS Kubernetes Benchmark and (in future) other frameworks.

Public surface:
    load_benchmark(version)           - load a benchmark YAML file
    Orchestrator(runners).run(...)    - execute all checks against a cluster
    APIRunner                         - Tier 1 (pure kubectl/API reads)
"""

from cis.schema import (
    Audit,
    Benchmark,
    CheckDefinition,
    Expected,
    load_benchmark,
)
from cis.result import CheckResult, Status
from cis.runners.orchestrator import Orchestrator
from cis.runners.api_runner import APIRunner
from cis.runners.base import CheckRunner, RunnerContext

__all__ = [
    "Audit",
    "Benchmark",
    "CheckDefinition",
    "Expected",
    "load_benchmark",
    "CheckResult",
    "Status",
    "Orchestrator",
    "APIRunner",
    "CheckRunner",
    "RunnerContext",
]
