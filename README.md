# K8s YAML Misconfiguration Checker Agent by Jayden Aung

A true AI security agent for Kubernetes manifests. Claude drives the analysis using the
Anthropic tool_use API — deciding which checks to run, scanning images for CVEs, and
identifying compound risk scenarios that static rules alone cannot catch.

## How it works

Instead of a fixed pipeline, Claude acts as an autonomous agent with tools:

```
📂 load_manifest      → parse the YAML, discover resources
🔍 run_check          → run static security checks (individual or all 14)
🛡 lookup_image_cves  → scan container images for CVEs via Trivy
⚠  report_finding     → record AI-identified findings
✅ finish             → end analysis, emit report
```

Claude decides the order and depth of investigation based on what it finds.

## Features

- **Agentic loop** — Claude calls tools iteratively, not a one-shot prompt
- **14 static checks** covering CIS Benchmark, NSA/CISA hardening guide, OWASP K8s Top 10
- **CVE scanning** via Trivy for container images (optional)
- **AI-identified findings** — logic-level issues, compound risk chains, telco/CNF-specific concerns
- **Markdown report** with severity table, risk score, and remediation priority ordering
- **Multi-document YAML** support (multiple `---` separated resources)
- **CI/CD friendly** — exit code `2` on CRITICAL findings
- **40 unit tests** covering all static checks
- **Configurable model** via `--model` flag or `K8S_CHECKER_MODEL` env var

## Quick start

```bash
# 1. Clone the repo
git clone https://github.com/jaydenaung/k8s-yaml-misconfig-checker-agent.git
cd k8s-yaml-misconfig-checker-agent

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set your Anthropic API key
cp .env.example .env
# Edit .env and add your key — or export it directly:
export ANTHROPIC_API_KEY=your-key-here

# 5. Run the agent
python agent.py samples/vulnerable.yaml

# Save the report to a file
python agent.py samples/vulnerable.yaml --output reports/result.md

# Static checks only — no API key required
python agent.py samples/vulnerable.yaml --no-ai

# Raw JSON output — useful for piping to other tools
python agent.py samples/vulnerable.yaml --json

# Use a specific model (faster/cheaper or more capable)
python agent.py samples/vulnerable.yaml --model claude-haiku-4-5-20251001
```

## Configuration

| Method | Example |
|--------|---------|
| `.env` file | `ANTHROPIC_API_KEY=sk-ant-...` |
| Environment variable | `export ANTHROPIC_API_KEY=sk-ant-...` |
| Model override (CLI) | `--model claude-haiku-4-5-20251001` |
| Model override (env) | `K8S_CHECKER_MODEL=claude-haiku-4-5-20251001` |

Default model: `claude-sonnet-4-6`

## Optional: CVE scanning with Trivy

If [Trivy](https://aquasecurity.github.io/trivy/) is installed, the agent will
automatically scan container images for known CVEs. Without it, that step is skipped
gracefully and everything else still works.

```bash
brew install trivy   # macOS
```

## Running tests

```bash
pytest tests/ -v
```

40 unit tests cover all 14 static checks — both positive (finding detected) and negative
(no finding) cases. Tests run offline with no API key required.

## Static checks covered

| Check ID | Category | Severity |
|----------|----------|----------|
| K8S-001 | Privileged container | CRITICAL |
| K8S-002 | Host namespaces (PID / IPC / Network) | CRITICAL / HIGH |
| K8S-003 | Root user (UID 0 or runAsNonRoot: false) | HIGH / MEDIUM |
| K8S-004 | Dangerous capabilities (SYS_ADMIN, ALL, …) | CRITICAL / HIGH |
| K8S-005 | Writable root filesystem | MEDIUM |
| K8S-006 | Missing resource limits / requests | MEDIUM / LOW |
| K8S-007 | Unpinned image tag (:latest or no tag) | MEDIUM |
| K8S-008 | Service account token auto-mount | MEDIUM |
| K8S-009 | hostPath volumes | CRITICAL / HIGH |
| K8S-010 | Missing labels (NetworkPolicy targeting) | LOW |
| K8S-011 | Hardcoded secrets in env vars | HIGH |
| K8S-012 | Missing liveness / readiness probes | LOW |
| K8S-013 | Missing pod-level securityContext / seccomp | MEDIUM |
| K8S-014 | RBAC wildcard verbs or resources | CRITICAL / HIGH |

## Project structure

```
k8s-yaml-misconfig-checker-agent/
├── agent.py          # Entry point — CLI arg parsing, orchestration
├── analyzer.py       # YAML parser, static checks, CHECK_REGISTRY
├── claude_agent.py   # Agentic loop using Anthropic tool_use API
├── tools.py          # Tool schemas (JSON) + execution functions
├── reporter.py       # Markdown report renderer
├── requirements.txt
├── .env.example      # API key template — copy to .env
├── CONTRIBUTING.md   # Guide for adding checks, tools, and tests
├── tests/
│   └── test_analyzer.py  # 40 unit tests for static checks
├── samples/
│   ├── vulnerable.yaml   # Intentionally broken manifest — for testing
│   └── secure.yaml       # Hardened example
└── reports/              # Output directory (gitignored)
```

## CI/CD integration

```yaml
# GitHub Actions example
- name: K8s security check
  run: |
    pip install -r requirements.txt
    python agent.py k8s/deployment.yaml --output reports/security.md
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Exit codes: `0` = clean, `1` = error, `2` = CRITICAL findings detected.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add new static checks, new agent tools,
run the test suite, and submit pull requests.

## Extending

**Add a static check:** implement a function in `analyzer.py` that takes `(resource, context)`
and returns a finding dict or `None`, then register it in `CHECK_REGISTRY` and add tests.

**Add a tool:** define its JSON schema in the `TOOLS` list in `tools.py`, add an execution
function, and wire it into the `execute_tool` dispatcher. Claude will start calling it
automatically.

**Tune the agent's focus:** adjust `SYSTEM_PROMPT` in `claude_agent.py` to bias Claude
toward specific workload types — 5G core NFs, CNF sidecars, service mesh, DPDK, etc.
