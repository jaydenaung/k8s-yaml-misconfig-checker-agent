# Copyright 2026 Jayden Aung — Apache 2.0
"""
cis/parsers/ — Audit parsers. Each parser is a callable that takes
(audit_params, ctx) and returns ParserOutput, or raises ParserError when
the environment does not support the check (e.g. managed control plane).

New audit.type identifiers are added by registering a new parser here.
"""

from cis.parsers.base import ParserError, ParserNotApplicable, ParserOutput
from cis.parsers.static_pod_arg import parse_static_pod_arg, parse_static_pod_arg_absent
from cis.parsers.rbac import parse_rbac_subject_count
from cis.parsers.default_sa import parse_default_sa_automount


PARSERS = {
    "static_pod_arg":        parse_static_pod_arg,
    "static_pod_arg_absent": parse_static_pod_arg_absent,
    "rbac_subject_count":    parse_rbac_subject_count,
    "default_sa_automount":  parse_default_sa_automount,
}


__all__ = [
    "PARSERS",
    "ParserError",
    "ParserNotApplicable",
    "ParserOutput",
]
