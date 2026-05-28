# Copyright 2026 Jayden Aung — Apache 2.0
"""
cis/parsers/base.py — Parser contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ParserOutput:
    """The observed value plus a string describing where it came from."""
    actual_value: Optional[str]
    evidence_source: str


class ParserError(Exception):
    """Raised when a parser hits an unrecoverable error talking to the cluster."""


class ParserNotApplicable(Exception):
    """
    Raised when the check is not applicable in this environment.

    Example: control-plane static-pod checks on a managed cluster (EKS, GKE),
    where the control plane is not visible to kubectl.
    """
