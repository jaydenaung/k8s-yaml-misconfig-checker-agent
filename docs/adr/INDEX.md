# KubeSentinel — R&D Decision Log

**Author:** Jayden Aung
**Repository:** kubesentinel
**Document path:** `docs/adr/INDEX.md`
**Document type:** Architecture Decision Records (ADR) + product narrative
**Last updated:** 2026-05-27
**Document conventions:** every architectural or product decision is captured as an ADR with **Context**, **Options considered**, **Decision**, **Rationale**, and **Consequences**. Decisions are numbered and append-only — superseded ADRs are marked as such rather than rewritten.

---

## Table of Contents

1. Product positioning and vision
2. The CIS scanner feature — narrative timeline
3. Architecture Decision Records (ADR-001 through ADR-009)
4. Product roadmap
5. Implementation log — Slice 1 (CIS framework + Tier 1)
6. Open questions for Slice 2

---

## 1. Product positioning and vision

KubeSentinel is positioned as an **AI-powered Kubernetes security platform that closes the detection-to-remediation loop**. Where traditional scanners (kubesec, kubeaudit, kube-bench, Polaris, Trivy) follow `Ingest → Detect → Surface → Human decides → Human acts`, KubeSentinel follows `Observe → Reason → Patch → Explain → Human approves`.

**Strategic intent.** The founder's stated goal is enterprise-grade architecture with an explicit eye toward acquisition, investment, or hiring on architectural credentials. This shapes every decision below: we optimise for the technical and product signals that diligence teams at potential acquirers care about, not for short-term feature velocity at the cost of long-term shape.

**Competitive context.** Meaningful exits in this space (Wiz, Orca, Snyk-acquired Fugue, Aqua's tuck-ins, Sysdig, Lacework, Twistlock/Palo Alto) all share one architectural property: they go invasive into the cluster when scanning, but increasingly in *agentless* form (ephemeral scan workloads, not persistent DaemonSets). KubeSentinel's design embraces this pattern explicitly.

---

## 2. The CIS scanner feature — narrative timeline

| Date | Milestone |
|---|---|
| 2026-05-27 | Founder raises feature request: scan control plane + worker nodes against CIS Kubernetes Benchmark |
| 2026-05-27 | Strategic discussion: trust posture, M&A signal, deployment model |
| 2026-05-27 | Decision: invasive-with-guardrails ("Trusted Scan Mode" pattern) |
| 2026-05-27 | MVP scope agreed: framework + Tier 1 API runner + GUI integration |
| 2026-05-27 | Slice 1 implementation completed: 20 CIS checks, 28 new tests, end-to-end CLI + dashboard |

**Genesis question (founder, paraphrased):** "How do I add CIS benchmark scanning of control plane and worker nodes, enterprise-grade, with M&A in mind? Should it be CLI, GUI, or both?"

**Substantive constraints emerged in discussion:**
- Must preserve audit trail (read-only history of every scanner action)
- Must work on managed clusters (EKS / GKE / AKS) with graceful degradation
- Must avoid scaring CISOs in security review
- Must be air-gap friendly (no remote fetches at scan time)
- Must support eventually replacing kube-bench in the buyer's mental model

---

## 3. Architecture Decision Records

### ADR-001 — Tiered execution model

**Status:** Accepted
**Date:** 2026-05-27
**Supersedes:** —

**Context.** The CIS Kubernetes Benchmark is not uniformly API-queryable. Checks split into three categories: (a) API-queryable (kube-apiserver flags via static pod specs, RBAC bindings via cluster API), (b) node-local (file permissions, file ownership, process arguments on disk), (c) logical/policy (RBAC graph analysis, default ServiceAccount behavior). Each requires fundamentally different execution semantics. kube-bench (the incumbent) chose all-in node-local execution via Job/DaemonSet with hostPath mounts.

**Options considered.**
1. **API-only.** Pure read-only kubectl. Cleanest trust story, but blind to ~40% of CIS controls.
2. **Node-local only (kube-bench style).** Full capability, but always-deploys-privileged-pod posture.
3. **Tiered.** API-only by default; opt-in escalation to ephemeral privileged Jobs; further opt-in to continuous monitoring.

**Decision.** Tiered model with four tiers:
- **Tier 0** — Manifest scan (pre-existing functionality, no cluster contact)
- **Tier 1** — API-only cluster scan (default for live clusters)
- **Tier 2** — Trusted Scan Mode (ephemeral, signed, scoped privileged Jobs)
- **Tier 3** — Continuous Sentinel (long-lived but scoped scanner pod — roadmap)

**Rationale.** Tiering preserves the read-only narrative as the *default* while admitting capability where customers explicitly approve it. This is the Wiz/Orca shape — "agentless but powerful". A pure read-only product is procurement-friendly but capability-limited (40% of CIS controls unaddressed). A pure node-local product is capable but has a poor security review story. Tiering wins on both axes by letting the customer choose per-scan.

**Consequences.**
- Code structure must support runner registration so Tier 2 plugs in without changing Tier 1 or the orchestrator.
- Database schema must support "this scan used Tier 1 only" vs "this scan used Tier 2" as first-class metadata.
- UI must surface tier choice clearly with the implications of each, never silently invasive.

---

### ADR-002 — Trusted Scan Mode pattern

**Status:** Accepted (specification — implementation in Slice 2)
**Date:** 2026-05-27
**Supersedes:** —

**Context.** Tier 2 needs to be invasive (deploy a privileged Job into the customer's cluster) without violating the trust posture that defaults to read-only. The customer must perceive Tier 2 as a deliberate, bounded, audited act, not a blank cheque.

**Decision.** Tier 2 follows five non-negotiable properties, collectively branded "Trusted Scan Mode":

1. **Ephemeral.** All invasive workloads run as `Job` with `ttlSecondsAfterFinished` ≤ 300. Never `Deployment`, never `DaemonSet`.
2. **Scoped.** Ships with a pre-written least-privilege `ClusterRole` the customer applies once. Never asks for cluster-admin. Dedicated namespace.
3. **Signed and reproducible.** Scanner container image is signed with cosign keyless (sigstore) and ships an SBOM. Customers and diligence teams can verify exactly what code ran in their cluster.
4. **User-approved per scan.** Dashboard surfaces a confirmation modal with the exact actions about to be taken. CLI requires `--yes` to bypass the prompt.
5. **Tamper-evident audit log.** Every Tier 2 deploy is logged to a `scan_audit` table (append-only) with timestamp, user, kubeconfig hash, Job manifest hash, ConfigMap-results hash.

**Rationale.** Each property defends against a specific objection in a security review. Together, they constitute the architectural moat: anyone can deploy a privileged pod, but the engineering value is in making it auditable, scoped, ephemeral, and signed.

**Consequences.**
- Requires GHCR-published, cosign-signed image pipeline (one-day CI setup).
- Requires `scan_audit` table in the schema (deferred to Slice 2 but already shaped for).
- Marketing artifact: this is the "5-bullet slide" we put in any pitch deck.

---

### ADR-003 — Read-only vs invasive trust posture

**Status:** Accepted
**Date:** 2026-05-27
**Supersedes:** —

**Context.** The original KubeSentinel posture is strictly read-only (no cluster mutations, ever). Adding CIS forces a choice: stay read-only and accept the 40% capability gap, or admit invasiveness with guardrails.

**Options considered.**
1. **Stay read-only.** Tier 1 only, ever. Honest scope, weaker market position.
2. **Go invasive without guardrails.** kube-bench-style: just deploy the privileged Job, no fanfare. Maximum capability, weakest security-review story.
3. **Invasive with guardrails.** Tier 2 Trusted Scan Mode (ADR-002).

**Decision.** Option 3 — invasive with guardrails.

**Rationale.** Strategic, not technical. Every meaningful K8s security exit in the last 4 years has gone invasive. Pure read-only positions the product as a tool, not a platform; tools don't get platform-level valuations. The Wiz/Orca generation proved that "agentless with ephemeral privileged scans" is the contemporary winning model — it preserves the marketing posture of read-only-by-default while enabling capability parity with the kube-bench/Aqua/Sysdig generation.

**Consequences.**
- Architecture must be designed for invasive *from day one*, even though Slice 1 only ships read-only Tier 1. Bolting invasive on later produces a bolted-on design.
- The narrative shifts from "we are a YAML scanner" to "we are a Kubernetes security platform with three deployment models, all auditable."

---

### ADR-004 — CLI and GUI as parallel surfaces; GUI primary for compliance

**Status:** Accepted
**Date:** 2026-05-27
**Supersedes:** —

**Context.** Question: is CIS scanning a CLI feature, a GUI feature, or both?

**Decision.** Both, but GUI is the *primary* surface for compliance; CLI is a thin extension of the same scanner core.

**Rationale.** Compliance is a *dashboard* workflow. Compliance officers don't use CLIs. The artefacts auditors want — per-control evidence, trend charts over time, exportable PDFs, exception management with sign-offs — all live in dashboards. The CLI is essential for CI/CD gating ("don't promote to prod if CIS score regresses") and on-call headless use, but its surface area is smaller: same scanner core, JSON output, exit code 2 on critical failure.

**Consequences.**
- The scanner core must be a library callable from both surfaces. We achieve this by putting all CIS logic under `cis/` with no FastAPI or CLI coupling, then thin wrappers in `web/cis_scanner.py` and `agent.py`.
- The CLI emerges almost for free once the GUI scanner is built.

---

### ADR-005 — Separate `compliance_results` table; do not overload `findings`

**Status:** Accepted
**Date:** 2026-05-27
**Supersedes:** —

**Context.** CIS results could be persisted into the existing `findings` table (vulnerability findings, AI findings, compound risk findings already share this table) or into a new dedicated table.

**Options considered.**
1. **Overload `findings`.** Add a `framework` column, treat CIS results as a kind of finding with `severity = status`. Schema reuse, fewer migrations.
2. **Separate `compliance_results` table.** Distinct columns for expected vs actual, structured evidence, PASS/FAIL/SKIP/MANUAL/ERROR status semantics independent of severity.

**Decision.** Option 2.

**Rationale.** The two domains have fundamentally different status semantics, evidence shapes, and downstream access patterns:

| Concern | `findings` | `compliance_results` |
|---|---|---|
| Status | severity (CRITICAL/HIGH/...) | PASS/FAIL/SKIP/MANUAL/ERROR |
| Evidence | free-text `detail` | structured `expected_value`, `actual_value`, `source` |
| Audit need | "found N vulnerabilities" | "control C was checked, observed X, against expected Y, at T" |
| Trend access | severity rollups | per-control time series |
| Suppression | by check_id + resource | by control_id + cluster + sign-off |

Trying to overload `findings` forces compromises in both domains. Clean domain separation is also a signal acquirer diligence teams notice — *"they understood compliance is a distinct domain from vulnerability management on day one."*

**Consequences.**
- New `ComplianceResult` SQLAlchemy model in `web/database.py`.
- `Scan` table gets nullable `framework` (e.g. `cis-kubernetes-1.9`) and a denormalised `compliance_score` for fast list rendering.
- Idempotent `_migrate()` ALTER TABLE additions keep existing deployments upgrading silently.

---

### ADR-006 — Polymorphic `audit.type` in benchmark YAML

**Status:** Accepted
**Date:** 2026-05-27
**Supersedes:** —

**Context.** Each CIS check needs to declare *how* it is audited. The YAML schema can either be flat (one field per concept) or polymorphic (a `type` discriminator with type-specific parameters).

**Decision.** Polymorphic: each check has `audit.type` (string identifier) plus type-specific parameters. New audit kinds register a new parser and a new `audit.type` value; existing checks are not touched.

```yaml
audit:
  type: static_pod_arg
  namespace: kube-system
  label_selector: "component=kube-apiserver"
  container: kube-apiserver
  arg: --anonymous-auth
```

**Rationale.** CIS publishes new benchmark versions multiple times per year. Adding a check type (kubelet `/configz` parsing, file-perm checks via Tier 2, certificate expiry checks) should be data plus one parser, never a schema breaking change. Polymorphism makes the schema additive forever.

**Consequences.**
- Parser registry pattern in `cis/parsers/__init__.py`. New audit types register as `PARSERS["new_type"] = parser_fn`.
- Runners dispatch by `audit.type` to the registered parser; the runner itself is type-agnostic.

---

### ADR-007 — CIS check IDs match the official CIS numbering

**Status:** Accepted
**Date:** 2026-05-27
**Supersedes:** —

**Context.** Internal check IDs could follow our own numbering (`CIS-001`, `CIS-002`, ...) or mirror the official benchmark numbering (`CIS-1.2.1`, `CIS-1.2.16`).

**Decision.** Mirror official numbering. `CIS-1.2.1` is the only acceptable form.

**Rationale.** Auditors and compliance reviewers will grep their official CIS PDF for "1.2.16" and expect to find it in our output. Internal numbering creates an unnecessary translation step at the worst possible time (during an audit). This is the kind of small choice that costs nothing in the codebase and pays off forever in human-friendly evidence.

**Consequences.**
- Check IDs are strings, not integers. The schema treats them as opaque labels.
- When we add a custom check (non-CIS), it gets a non-CIS prefix (`KS-` for KubeSentinel-original, etc.) to keep the namespaces clean.

---

### ADR-008 — 20-check MVP scope (control plane + RBAC), worker checks deferred to Slice 2

**Status:** Accepted
**Date:** 2026-05-27
**Supersedes:** —

**Context.** CIS Kubernetes Benchmark v1.9 has ~80 checks. Shipping all of them in Slice 1 is unrealistic; cherry-picking randomly wastes the slice.

**Decision.** 20 checks in Slice 1, chosen for **enterprise demo value**:
- 9 × API server (anonymous-auth, token-auth-file, authorization-mode, profiling, audit-log-path, service-account-lookup, kubelet-cert)
- 3 × Controller manager
- 2 × Scheduler
- 3 × etcd
- 3 × RBAC / policies (cluster-admin minimization, default SA usage)

All 20 are Tier 1 — pure API reads. Worker-node checks (file perms, kubelet config on disk) are intentionally deferred to Slice 2 (Tier 2 / Trusted Scan Mode).

**Rationale.** A CISO opening the dashboard will look at the control plane first — that's where the headlines live. RBAC is the second look. Worker node file permissions are important but never the first thing reviewed. We hit the high-attention surface with 20 checks and prove the framework works end-to-end. The remaining 60 checks are mostly mechanical fills once Tier 2 ships.

**Consequences.**
- MVP demo: scan a cluster, see 20 controls, score, evidence — credible.
- Roadmap: Slice 2 expands the benchmark file to ~60 checks total (adding worker-node and policy-tier checks) once Tier 2 is operational.

---

### ADR-009 — Promote GUI from "fast-follow" to Slice 1 MVP

**Status:** Accepted (revised mid-slice)
**Date:** 2026-05-27
**Supersedes:** Original MVP plan (CLI-only in Slice 1)

**Context.** Original Slice 1 scope was CLI-only: build the framework + Tier 1 runner, ship `python agent.py --cis`, defer the dashboard to Slice 2. Mid-discussion, the founder pushed back: "I think we should add the feature to GUI."

**Decision.** Promote the compliance dashboard into Slice 1. Build the two-page UI (list + detail) alongside the CLI.

**Rationale.**
- CIS is a dashboard activity (see ADR-004). A CLI-only compliance feature does not survive an enterprise demo.
- The existing infrastructure (FastAPI, SQLAlchemy, BackgroundTask, Jinja2 templates, APScheduler) means adding a UI is +40-50% scope, not 100%.
- An acquirer's technical diligence team that opens the product and sees CLI-only compliance reads it as "infrastructure built, product not finished." Same code, very different signal.
- Restraint: the UI is intentionally minimal. No trend charts, no PDF export, no exception workflow. Just per-control pass/fail with evidence and remediation. Polish lives in Slice 2.

**Consequences.**
- Slice 1 wall time: ~3 weeks instead of ~2. Acceptable given the demo value gained.
- Two new templates (`compliance_list.html`, `compliance_detail.html`), one new router (`web/routes/compliance.py`), one new BackgroundTask wrapper (`web/cis_scanner.py`).
- Sets the UX vocabulary for compliance (score pill, status badges, section grouping). Future compliance frameworks (NIST, SOC2 mapping) reuse the same UI vocabulary.

---

## 4. Product roadmap

### Slice 1 — CIS framework + Tier 1 API runner + dashboard ✅ **Shipped 2026-05-27**

- Declarative YAML benchmark format with polymorphic `audit.type`
- 20 CIS Kubernetes 1.9 checks (control plane + RBAC)
- `APIRunner` + `Orchestrator` (Tier 1, pure read-only API)
- `ComplianceResult` table + `Scan.framework` / `Scan.compliance_score` columns
- Compliance dashboard: list view (clusters + scores), detail view (per-control evidence)
- CLI: `python agent.py --cis [--kubeconfig PATH] [--json]`
- 28 new unit tests (76 total, all green)

### Slice 2 — Trusted Scan Mode (Tier 2) — *Next*

- cosign-signed scanner container image published to GHCR
- Least-privilege ClusterRole + RoleBinding shipped as YAML in repo
- `scan_audit` append-only table (tamper-evident log of every Tier 2 deploy)
- Worker-node checks: kubelet args (`--anonymous-auth`, `--authorization-mode`, `--read-only-port`), file permissions (`/etc/kubernetes/admin.conf`, kubelet binary)
- Dashboard: "Run Tier 2 Scan" confirmation modal with action preview
- CLI: `--tier 2 --yes` for headless execution

### Slice 3 — Compliance evidence export

- PDF export of scan results (auditor-friendly)
- SARIF export for CI tooling integration
- CSV per-control export for spreadsheet analysis

### Slice 4 — Compliance intelligence

- Score drift detection ("CIS-1.2.16 regressed on prod-eu1 between $LAST_WEEK and $TODAY")
- Cross-cluster compliance rollup view ("47 production clusters, sortable by score")
- Exception workflow with `accepted_by`, `accepted_at`, `review_due`, `compensating_control` fields
- NIST 800-53 / SOC2 CC / ISO 27001 control-mapping in the detail view

### Slice 5 — Managed cluster profiles

- CIS EKS 1.5, CIS GKE 1.6, CIS AKS profile YAML files
- Automatic cluster-vendor detection (kubectl version, cloud-provider node labels)
- Profile auto-selection per cluster

### Slice 6 — Continuous Sentinel (Tier 3)

- Long-lived but tightly scoped scanner deployment
- Watches for drift events (kube-apiserver flag changed at 03:14 UTC)
- Webhook / email alerts on score regression
- This is the ARR upsell; pricing tier separated from one-shot scans

### Slice 7 — Multi-agent reasoning

- Triage agent: groups findings into coherent incidents
- Remediation agent: generates and (after approval) opens fix PRs against source repos
- Compliance agent: assembles audit evidence packages on demand
- Orchestrator agent: coordinates the above

---

## 5. Implementation log — Slice 1

**Files created (15)**

```
cis/
  __init__.py
  schema.py
  result.py
  benchmarks/
    cis_kubernetes_1_9.yaml          # 20 checks
  parsers/
    __init__.py
    base.py
    static_pod_arg.py
    rbac.py
    default_sa.py
  runners/
    __init__.py
    base.py
    api_runner.py
    orchestrator.py
tests/
  cis_fixtures/                       # 6 JSON fixtures
  test_cis_schema.py                  # 6 tests
  test_cis_parsers.py                 # 11 tests
  test_cis_runner.py                  # 11 tests
web/
  cis_scanner.py
  routes/compliance.py
  templates/compliance_list.html
  templates/compliance_detail.html
```

**Files modified (4)**

- `agent.py` — `--cis`, `--kubeconfig`, `--cis-version` flags; `_run_cis()`; `_cis_exit_code()`
- `server.py` — registered `compliance.router`
- `web/database.py` — `ComplianceResult` model; new columns on `Scan` (`framework`, `compliance_score`, `pass_count`, `fail_count`, `skip_count`, `manual_count`); idempotent migrations
- `web/templates/base.html` — Compliance nav link; CIS status badge styles; score pill styles

**Test posture**

- Total tests: **76 passed** (48 pre-existing + 28 new)
- All CIS tests are offline (parser kubectl calls monkeypatched against JSON fixtures)
- End-to-end verified against a local Docker Desktop cluster: 50% score, 10 PASS / 10 FAIL, exit code 2 on HIGH FAIL (CI-suitable)

**Deferred items (intentionally)**

- PDF / CSV / SARIF export → Slice 3
- Score trend over time → Slice 4
- Exception workflow → Slice 4
- Compliance framework mappings (NIST, SOC2, ISO) display → Slice 4 (data already captured per-check in `references`)
- Managed cluster auto-detection → Slice 5
- AI-driven contextual remediation narratives (beyond static `remediation` strings) → Slice 6 candidate

---

## 6. Open questions for Slice 2

These need explicit decisions before Slice 2 begins. Capturing them now so they're not forgotten:

1. **Scanner image registry.** GHCR (`ghcr.io/jaydenaung/kubesentinel-scanner`) vs Docker Hub vs a private registry. GHCR is recommended (free for public images, signs cleanly with cosign keyless, lives next to the source repo).
2. **Tier 2 namespace name.** `kubesentinel-scan` vs allowing the customer to choose. Recommended: ship as a Helm value or env var with `kubesentinel-scan` as the default.
3. **ClusterRole shape.** Strict least-privilege (`get pods` in `kube-system`, `get nodes/proxy`) vs a pragmatic superset. Recommended: strict, with the doc explicitly enumerating each verb/resource.
4. **Audit log retention.** Forever (append-only, never truncated) vs configurable retention. Recommended: forever for the MVP. SOC2 evidence requires multi-year retention anyway.
5. **Job results channel.** ConfigMap (simple, capped at 1 MiB) vs Secret (allows base64 binary) vs a temporary PVC. Recommended: ConfigMap for the MVP; revisit when a check needs to ship >500 KB of output.
6. **CLI tier flag.** `--tier 2` vs `--trusted-scan` vs implicit (detect when a check needs node access). Recommended: explicit `--tier 2` with a confirmation prompt that `--yes` bypasses.

---

## Appendix A — How to add an ADR

New ADRs are append-only. Use the next available number:

```markdown
### ADR-NNN — Short title

**Status:** Proposed | Accepted | Superseded by ADR-MMM | Deprecated
**Date:** YYYY-MM-DD
**Supersedes:** ADR-XXX, ADR-YYY  (or — if none)

**Context.** What is the decision about? What was triggering it?

**Options considered.** Numbered list. Mention the option you chose AND the
options you didn't, with one-line summaries each.

**Decision.** What was actually chosen.

**Rationale.** Why this option won. Quote the strategic concern that tipped it.

**Consequences.** What this means for the code, the schema, the user, the
roadmap. Both costs and benefits.
```

Never edit a Accepted ADR — supersede it with a new one and update the old one's `Status:` line.

---

## Appendix B — Maintaining this archive

This file is committed to the repo at `docs/adr/INDEX.md` — every ADR addition is captured by git with author, timestamp, and diff. That's the load-bearing property for acquisition diligence: the trail is immutable evidence, not a Word doc someone might have edited yesterday.

**Workflow for new ADRs:**

1. Append the new ADR using the template in Appendix A. Use the next free number.
2. Add a row to the timeline table (Section 2) if the decision belongs to a new feature slice.
3. If the decision changes the roadmap, update Section 4.
4. Update the **Last updated** line at the top of this document.
5. Commit alongside the code change that implements (or precedes) the decision:

```bash
git add docs/adr/INDEX.md <code files affected>
git commit -m "docs(adr): ADR-NNN — short title; <one line on what changed>"
```

**When to split into one-file-per-ADR:** if this index passes ~30 ADRs or 50 KB, migrate to `docs/adr/0001-tiered-execution-model.md` (one file per ADR) and turn this INDEX.md into a table of contents linking out to each. Until then, the single-file archive is easier to read and to diff.

---

*KubeSentinel — AI-Powered Kubernetes Security Platform · Copyright 2026 Jayden Aung · Apache License 2.0*
