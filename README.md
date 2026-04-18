# K8s YAML Misconfiguration Checker by Jayden Aung

AI-powered Kubernetes security analysis agent. Combines fast static rule checks with
Claude-powered contextual analysis — including telco/CNF-specific risk scoring.

## Features

- 14 static checks (CIS Benchmark, NSA/CISA hardening guide, OWASP K8s Top 10)
- Claude AI layer for deeper contextual analysis and attack narratives
- Telco/CNF relevance scoring for each finding
- Markdown report output with remediation priority ordering
- Works on multi-document YAML files
- Exit code 2 on CRITICAL findings (CI/CD pipeline friendly)

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set your Anthropic API key
export ANTHROPIC_API_KEY=your-key-here

# 3. Run against the vulnerable sample
python agent.py samples/vulnerable.yaml

# 4. Save report to file
python agent.py samples/vulnerable.yaml --output reports/vulnerable.md

# 5. Run static checks only (no API key needed)
python agent.py samples/vulnerable.yaml --no-ai

# 6. JSON output (useful for piping to other tools)
python agent.py samples/vulnerable.yaml --json
```

## Static checks covered

| Check ID | Category            | Severity        |
|----------|---------------------|-----------------|
| K8S-001  | Privileged container | CRITICAL        |
| K8S-002  | Host namespaces (PID/IPC/Network) | CRITICAL/HIGH |
| K8S-003  | Root user           | HIGH            |
| K8S-004  | Dangerous capabilities | CRITICAL/HIGH |
| K8S-005  | Writable root filesystem | MEDIUM       |
| K8S-006  | Missing resource limits | MEDIUM/LOW    |
| K8S-007  | Unpinned image tag  | MEDIUM          |
| K8S-008  | SA token auto-mount | MEDIUM          |
| K8S-009  | hostPath volumes    | CRITICAL/HIGH   |
| K8S-010  | Missing labels (NetworkPolicy) | LOW      |
| K8S-011  | Hardcoded secrets in env | HIGH        |
| K8S-012  | Missing probes      | LOW             |
| K8S-013  | Missing securityContext / seccomp | MEDIUM |
| K8S-014  | RBAC wildcard rules | CRITICAL/HIGH   |

## Project structure

```
k8s-misconfig-checker/
├── agent.py          # Main entry point
├── analyzer.py       # YAML parser + static checks
├── claude_agent.py   # Anthropic API integration
├── reporter.py       # Markdown report renderer
├── requirements.txt
├── samples/
│   ├── vulnerable.yaml   # Intentionally broken — for testing
│   └── secure.yaml       # Hardened example
└── reports/              # Output directory
```

## CI/CD integration

```yaml
# GitHub Actions example
- name: K8s security check
  run: |
    python agent.py k8s/deployment.yaml --output reports/security.md
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Exit codes: `0` = pass, `1` = error, `2` = CRITICAL findings detected.

## Extending

Add new static checks in `analyzer.py` — each check function receives the full resource
dict and the context string, and returns either `None` (pass) or a finding dict.

The Claude prompt in `claude_agent.py` can be tuned to focus on specific workload types
(5G core, CNF sidecars, service mesh, etc.).
