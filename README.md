# KubeSentinel — AI-Powered Kubernetes Security Platform

> **Detect. Reason. Fix.** — The only Kubernetes security agent that generates AI-powered YAML remediation patches alongside every finding.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Model](https://img.shields.io/badge/Claude-claude--sonnet--4--6-blueviolet)](https://www.anthropic.com/)
[![Tests](https://img.shields.io/badge/tests-48%20passing-brightgreen.svg)](tests/)

---

## What Makes KubeSentinel Different

Traditional Kubernetes security tools follow the same loop:

> **Ingest → Detect → Surface → Human decides → Human acts**

KubeSentinel closes that loop:

> **Observe → Reason → Patch → Explain → Human approves**

The agent doesn't just find that `runAsRoot: true` is misconfigured — it generates the corrected YAML patch, explains why the change fixes the issue, and queues it for one-click approval. Static scanners report. KubeSentinel reasons and acts.

---

## Web Dashboard

![KubeSentinel Dashboard](img/kubesentinel1.png)

An on-prem security dashboard — runs on your internal network, accessible by IP. No SaaS dependency, no data leaves your environment.

---

## Architecture

```mermaid
graph TB
    subgraph Interfaces["User Interfaces"]
        CLI["CLI  python agent.py"]
        WEB["Web Dashboard  :8000"]
        GHA["GitHub Actions  PR Scanner"]
    end

    subgraph Server["FastAPI Server  server.py"]
        API["REST API"]
        AUTH["Session Auth  bcrypt"]
        SCHED["APScheduler  Scheduled Scans"]
        BG["BackgroundTask  Async Execution"]
    end

    subgraph Agent["AI Agent Layer  claude_agent.py"]
        LOOP["Agentic Loop  MAX 25 iterations"]
        CLAUDE["Claude claude-sonnet-4-6  tool_use API"]
        TOOLS["Tool Executor  tools.py"]
    end

    subgraph ToolSet["Agent Tools"]
        T1["load_manifest"]
        T2["render_helm_chart"]
        T3["query_cluster"]
        T4["run_check  14 static checks"]
        T5["lookup_image_cves"]
        T6["report_finding"]
        T7["suggest_patch ★ NEW"]
        T8["finish"]
    end

    subgraph Storage["Data Layer"]
        DB[("SQLite  data/kubesentinel.db")]
        FS["File Store  data/uploads/"]
    end

    subgraph External["External Systems"]
        K8S["Kubernetes Cluster  kubectl"]
        TRIVY["Trivy  CVE Database"]
        GH["GitHub  PR Comments"]
        HELM["Helm  chart rendering"]
    end

    CLI --> Agent
    WEB --> Server
    GHA --> CLI
    Server --> BG --> Agent
    SCHED --> Agent
    Agent --> LOOP --> CLAUDE --> TOOLS
    TOOLS --> T1 & T2 & T3 & T4 & T5 & T6 & T7 & T8
    T3 --> K8S
    T5 --> TRIVY
    Agent --> Storage
    Server --> Storage
    Server --> AUTH
    GHA --> GH
```

### How the agentic loop works

Claude receives the manifest or cluster target and iteratively calls tools — it decides the order and depth of investigation based on what it finds. When it identifies a misconfiguration (via static check or its own reasoning), it immediately calls `suggest_patch` to generate a corrected YAML snippet. The agent runs for up to 25 iterations before calling `finish`.

```
load_manifest / render_helm_chart
        ↓
run_check(ALL)                    ← 14 static checks across all resources
        ↓
lookup_image_cves                 ← Trivy scan per unique image
        ↓
query_cluster                     ← kubectl: pods, RBAC, NetworkPolicies, Secrets
        ↓
probe_service_account             ← runtime SA permission proof via kubectl auth can-i ★
        ↓
report_finding                    ← AI-identified issues static checks missed
suggest_patch                     ← corrected YAML patch for every finding  ★
        ↓
finish
```

---

## Core Capabilities

| Capability | Detail |
|---|---|
| **AI-powered remediation** | `suggest_patch` generates corrected YAML for every finding — critical, high, medium, low |
| **14 static checks** | CIS Benchmark, NSA/CISA Hardening Guide, OWASP K8s Top 10 |
| **Agentic reasoning** | Claude calls tools iteratively — not a fixed pipeline |
| **Live cluster analysis** | kubectl-based: pods, RBAC, NetworkPolicies, Secrets |
| **CVE scanning** | Trivy integration — top CVEs per severity, stored per scan |
| **Helm support** | `helm template` rendering before analysis |
| **Web dashboard** | Multi-user, scan history, scheduling, image CVE view |
| **PR-level scanning** | GitHub Actions — comment on PRs, block merge on CRITICAL |
| **Suppression allowlist** | Acknowledge accepted risks with audit trail |
| **Offline / static mode** | Full static analysis with no API key required |
| **CI/CD friendly** | Exit code `2` on CRITICAL — drop into any pipeline |

---

## Quick Start

### Prerequisites

- Python 3.10+
- An [Anthropic API key](https://console.anthropic.com/) (required for AI mode; static mode works without one)
- Optional: `kubectl`, `helm`, `trivy`

### 1 — Clone and set up environment

```bash
git clone https://github.com/jaydenaung/kubesentinel.git
cd kubesentinel

python3 -m venv venv
source venv/bin/activate          # macOS/Linux
# venv\Scripts\activate           # Windows

python -m pip install -r requirements.txt
```

### 2 — Configure your API key

```bash
cp .env.example .env
# Edit .env and set:  ANTHROPIC_API_KEY=sk-ant-your-key-here
```

Or export directly:

```bash
export ANTHROPIC_API_KEY=sk-ant-your-key-here
```

### 3 — Run your first scan

```bash
# AI agent scan (requires API key)
python agent.py samples/vulnerable.yaml

# Static checks only (no API key required)
python agent.py samples/vulnerable.yaml --no-ai

# Scan an entire directory
python agent.py k8s/

# Render and scan a Helm chart
python agent.py ./my-helm-chart/

# Output to Markdown report
python agent.py samples/vulnerable.yaml --output reports/result.md

# Raw JSON (pipe to other tools)
python agent.py samples/vulnerable.yaml --json
```

### 4 — Start the web dashboard

```bash
python server.py                    # http://0.0.0.0:8000
python server.py --port 8080        # custom port
python server.py --host 127.0.0.1  # local-only
```

On first visit, a setup wizard creates your admin account.

---

## Step-by-Step Testing Guide

This section walks through validating every layer of KubeSentinel — from unit tests to end-to-end AI scanning.

### Step 1 — Run the unit test suite

```bash
source venv/bin/activate
pytest tests/ -v
```

Expected output: **48 tests pass**, covering all 14 static checks and the suppression allowlist. No API key or cluster connection required.

```
tests/test_analyzer.py::test_privileged_container PASSED
tests/test_analyzer.py::test_host_pid PASSED
...
tests/test_suppressor.py::test_suppress_by_check_id PASSED
========================= 48 passed in 0.42s =========================
```

### Step 2 — Static scan (no API key)

```bash
python agent.py samples/vulnerable.yaml --no-ai
```

Expect 10+ findings across CRITICAL and HIGH severities on the intentionally misconfigured sample manifest.

### Step 3 — AI agent scan with patch generation

```bash
export ANTHROPIC_API_KEY=sk-ant-your-key-here
python agent.py samples/vulnerable.yaml
```

Watch the agent tool calls in the terminal output:

```
      📂  load_manifest(path=samples/vulnerable.yaml)
      🔍  run_check(check=ALL  resource=-1)
      🛡  lookup_image_cves(nginx:latest)
      🌐  query_cluster(pods)
      ⚠  report_finding([CRITICAL] Privileged container with host namespaces ...)
      🔧  suggest_patch([K8S-001] Deployment/vulnerable-api)
      ✅  finish(Found 14 findings ...)
```

The `🔧 suggest_patch` calls confirm AI-generated patches are being produced and stored for every finding.

### Step 4 — Verify patch storage

```bash
# Check the generated report for patch content
python agent.py samples/vulnerable.yaml --json | python -m json.tool | grep -A5 "suggested_patch"
```

### Step 5 — Web dashboard end-to-end

```bash
python server.py
```

1. Open `http://localhost:8000` → complete the setup wizard (create admin account)
2. Navigate to **Manifests** → **Upload Manifest** → select `samples/vulnerable.yaml`
3. Choose **AI Agent** scan mode → click **Scan**
4. Watch the status badge cycle: `queued → running → done`
5. Click into the scan to view findings, severity breakdown, and AI-generated patches
6. Navigate to **Images** → confirm CVE counts appear (requires Trivy)

### Step 6 — Static-only web scan (no API key)

Repeat Step 5 with **Static** scan mode selected. Findings appear without an API key — useful for air-gapped environments.

### Step 7 — PR-level scanning (GitHub Actions)

Push a branch with changes to any `.yaml` file. The workflow at `.github/workflows/kubesentinel.yml` will:

1. Detect changed YAML files in the PR
2. Run AI + static analysis on those files only
3. Post a finding summary as a PR comment
4. Block merge if CRITICAL findings are detected

To test locally before pushing:

```bash
python agent.py --files samples/vulnerable.yaml --pr-comment
```

### Step 8 — Suppression allowlist

```bash
cp samples/.k8s-checker-ignore.yaml .
python agent.py samples/vulnerable.yaml --no-ai
```

Suppressed findings still appear in the report footer with their stated reason — providing an audit trail for compliance reviews.

---

## Web Dashboard Reference

| Page | What it does |
|---|---|
| Dashboard | Security posture overview — critical/high counts, recent scans, clear history |
| Manifests | Upload YAML → AI Agent or Static → findings + AI patches |
| Clusters | Onboard via kubeconfig → scan on demand or on schedule |
| Images | Container images across all scans — CVE counts + top CVEs by severity |
| Users | Admin: create accounts, activate/deactivate |

**Scan scheduling:** Set a recurring interval per cluster (6h / 12h / 24h / 48h / weekly). Runs via APScheduler — no cron, no external infrastructure.

**Data storage:** Everything in `data/` (SQLite + uploaded files). Gitignored. Kubeconfigs stored `chmod 600`.

---

## PR-Level Manifest Scanning (GitHub Actions)

Copy the workflow into your repo:

```bash
mkdir -p .github/workflows
curl -o .github/workflows/kubesentinel.yml \
  https://raw.githubusercontent.com/jaydenaung/kubesentinel/main/.github/workflows/kubesentinel.yml
```

Add `ANTHROPIC_API_KEY` as a GitHub Actions secret. On every PR touching `.yaml`/`.yml`, KubeSentinel will scan changed files, post findings as a PR comment, and fail the check on CRITICAL findings.

**PR comment format:**

```
🛡 KubeSentinel · ⛔ BLOCKED

⛔ 1 CRITICAL finding must be resolved before merging.

Scanned: deployment.yaml, rbac.yaml
Findings: 5 (3 static, 2 AI-identified)

| Severity  | Count |
|-----------|-------|
| 🔴 CRITICAL | 1   |
| 🟠 HIGH     | 2   |
| 🟡 MEDIUM   | 2   |
```

Without an API key, falls back to static checks only.

---

## Static Checks Reference

| Check ID | Category | Severity |
|---|---|---|
| K8S-001 | Privileged container | CRITICAL |
| K8S-002 | Host namespaces (PID / IPC / Network) | CRITICAL / HIGH |
| K8S-003 | Root user (UID 0 or runAsNonRoot: false) | HIGH / MEDIUM |
| K8S-004 | Dangerous capabilities (SYS_ADMIN, ALL, …) | CRITICAL / HIGH |
| K8S-005 | Writable root filesystem | MEDIUM |
| K8S-006 | Missing resource limits / requests | MEDIUM / LOW |
| K8S-007 | Unpinned image tag (`:latest` or no tag) | MEDIUM |
| K8S-008 | Service account token auto-mount | MEDIUM |
| K8S-009 | hostPath volumes | CRITICAL / HIGH |
| K8S-010 | Missing labels (NetworkPolicy targeting) | LOW |
| K8S-011 | Hardcoded secrets in env vars | HIGH |
| K8S-012 | Missing liveness / readiness probes | LOW |
| K8S-013 | Missing pod-level securityContext / seccomp | MEDIUM |
| K8S-014 | RBAC wildcard verbs or resources | CRITICAL / HIGH |

---

## Configuration Reference

| Method | Example |
|---|---|
| `.env` file | `ANTHROPIC_API_KEY=sk-ant-...` |
| Environment variable | `export ANTHROPIC_API_KEY=sk-ant-...` |
| Model override (CLI) | `--model claude-haiku-4-5-20251001` |
| Model override (env) | `K8S_CHECKER_MODEL=claude-haiku-4-5-20251001` |

Default model: `claude-sonnet-4-6`

Exit codes: `0` = clean, `1` = error, `2` = CRITICAL findings detected.

---

## Suppressing Accepted Risks

Create `.k8s-checker-ignore.yaml` to silence findings your team has reviewed. Suppressed findings appear in the report footer for auditability.

```yaml
suppress:
  - check_id: K8S-008
    resource: Deployment/legacy-api
    reason: "Migrating off auto-mounted SA tokens in Q3 2026 — JIRA-1234"

  - check_id: K8S-007
    reason: "Internal registry enforces immutable tags at push time"
```

---

## Roadmap

KubeSentinel is on a deliberate path from detection to autonomous remediation.

| Phase | Feature | Status |
|---|---|---|
| ✅ 1 | AI patch generation — `suggest_patch` produces corrected YAML for every finding | **Shipped** |
| 🔄 2 | Patch review UI — diff viewer with approve / reject workflow in the web dashboard | In progress |
| 📋 3 | GitHub PR creation — agent opens fix PRs against source repos after human approval | Planned |
| 📋 4 | Compliance report generator — map findings to CIS, NIST, SOC2 controls | Planned |
| 📋 5 | Findings relationship graph — model attack paths across CVE → image → deployment → RBAC | Planned |
| 📋 6 | Runtime signals — Falco / Kubernetes audit log integration | Planned |
| 📋 7 | Multi-agent architecture — triage, remediation, compliance, and orchestrator agents | Planned |

---

## Project Structure

```
kubesentinel/
├── agent.py              # CLI entry point — arg parsing, orchestration
├── analyzer.py           # YAML parser, 14 static checks, CHECK_REGISTRY
├── claude_agent.py       # Agentic loop using Anthropic tool_use API
├── tools.py              # Tool schemas + execution (incl. suggest_patch)
├── reporter.py           # Markdown and PR comment renderer
├── suppressor.py         # Suppression allowlist loader and filter
├── server.py             # FastAPI server entry point
├── requirements.txt
├── .env.example
├── CONTRIBUTING.md
├── .github/
│   └── workflows/
│       └── kubesentinel.yml  # PR-level manifest scanning
├── web/
│   ├── database.py       # SQLAlchemy models — User, Manifest, Cluster, Scan, Finding, Image
│   ├── auth.py           # Session auth, bcrypt password hashing
│   ├── scanner.py        # Background scan execution (manifest + cluster)
│   ├── scheduler.py      # APScheduler — scheduled cluster scans
│   ├── routes/           # FastAPI routers (dashboard, manifests, clusters, images, users, api)
│   └── templates/        # Jinja2 templates — dark-theme dashboard UI
├── tests/
│   ├── test_analyzer.py  # 40 unit tests — all 14 static checks
│   └── test_suppressor.py # 8 unit tests — suppression logic
├── samples/
│   ├── vulnerable.yaml              # Intentionally misconfigured manifest
│   ├── secure.yaml                  # Hardened reference manifest
│   └── .k8s-checker-ignore.yaml    # Example suppression config
└── data/                 # Runtime data — DB, uploads, kubeconfigs (gitignored)
```

---

## Optional: Install External Tools

```bash
# CVE scanning
brew install trivy          # macOS
# https://aquasecurity.github.io/trivy/ for other platforms

# Helm chart rendering
brew install helm

# kubectl — via your cloud provider CLI or:
# https://kubernetes.io/docs/tasks/tools/
```

All three are optional. KubeSentinel gracefully skips any step for which the tool is not installed.

---

## CI/CD Integration (Generic)

```yaml
# GitHub Actions — full repo scan on push to main
- name: KubeSentinel security check
  run: |
    python -m pip install -r requirements.txt
    python agent.py k8s/ --output reports/security.md
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

---

## Troubleshooting

**`ModuleNotFoundError`** — always use `python -m pip` inside an activated venv:

```bash
source venv/bin/activate
python -m pip install -r requirements.txt
which python   # should point inside venv/bin/
```

**`ANTHROPIC_API_KEY not set`**:

```bash
export ANTHROPIC_API_KEY=sk-ant-your-key-here
# or add to .env file in project root
```

**Port already in use**:

```bash
lsof -ti:8000 | xargs kill -9
python server.py
```

**Trivy / helm / kubectl not found** — these are optional; install only what you need. KubeSentinel logs a graceful skip and continues.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add static checks, agent tools, and tests.

**Add a static check:** implement a function in `analyzer.py` taking `(resource, context)`, returning a finding dict or `None`, register in `CHECK_REGISTRY`, add tests.

**Add an agent tool:** define its JSON schema in `TOOLS` in `tools.py`, add an execution function, wire into `execute_tool`. Claude starts calling it automatically.

---

## Disclaimer

KubeSentinel is provided for **informational and educational purposes only**.

- **Read-only** — KubeSentinel never modifies your cluster, manifests, or any external system. It only reads and reports.
- **No security guarantee** — A clean report does not mean your cluster is secure. Always combine with manual review, penetration testing, and defence-in-depth.
- **AI findings require human review** — Findings and patches marked `[AI]` are generated by a large language model. They may contain false positives or errors. Never apply an AI-generated patch without independent verification.
- **No warranty** — Provided "as is", without warranty of any kind. The author accepts no liability for damages of any kind.
- **Untrusted input** — Do not run KubeSentinel against YAML from untrusted sources without reviewing it first. Malicious YAML could contain prompt injection attempts.

> **TL;DR:** This is a reasoning and reporting tool, not a compliance auditor. It surfaces issues and suggests fixes for your engineers to review — it does not replace human judgment or formal security assessments.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 Jayden Aung
