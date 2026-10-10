# AI Security Log Copilot — MVP Feature Requirements

## 0. Scope and Principles

This document specifies five features to turn the existing prototype into an initial usable MVP. Preserve the current pipeline:

`Log → Parser → LogEvent → Detector → SecurityAlert → Incident Correlator → Evidence Graph → Hypotheses → Read-only Investigation`

- Reuse existing models, evidence IDs, detectors, and APIs where possible; do not rewrite working modules without a clear reason.
- The deterministic backend owns observed facts and alerts. The LLM may interpret evidence but must not invent evidence, assert unproven compromise, or execute system-changing actions.
- All imported log content is untrusted. Keep data local and make AI functionality optional.
- Clearly separate **required MVP behavior** from optional enhancements.

## Feature 1 — Custom Log Upload / Import

**Priority:** P0

### Goal
Allow users to analyze their own SSH and Nginx logs, rather than only built-in samples.

### Functional requirements
- Provide a UI for selecting one or multiple local log files in a single scan.
- Support existing SSH authentication-log and Nginx access-log formats; allow explicit log-type selection per file. Auto-detection is optional.
- Parse each file with the existing parser, merge normalized events, and run the existing detection/correlation/graph/hypothesis pipeline.
- Return a `scan_id`, per-file parse counts, accepted/rejected line counts, and useful error messages with line numbers where feasible.
- Permit partial success: malformed lines must not silently disappear or invalidate all valid lines; report skipped lines.
- Reject unsupported types, oversized uploads, and empty files with clear errors. Define configurable file-size and line-count limits.
- Treat uploaded filenames and contents as untrusted; do not execute or interpolate log text as commands.

### Suggested interface
- `POST /api/scans/upload` (`multipart/form-data`) accepting files and corresponding source types.
- Reuse existing scan retrieval endpoints and response models when practical.

### Acceptance criteria
- Uploading one SSH file yields the expected SSH alerts.
- Uploading SSH and Nginx files together produces cross-source incidents when warranted.
- An invalid file or malformed line generates visible feedback; no server crash.
- The resulting scan can be explored through existing incident, graph, and hypothesis views without relying on bundled samples.

## Feature 2 — Incident Report Export

**Priority:** P0

### Goal
Export an incident investigation as a portable, evidence-traceable report.

### Functional requirements
- Provide a **Download Markdown** action for each incident.
- Include incident ID, title, severity, time range, affected IPs/accounts, timeline, and associated alerts.
- Include observed evidence with stable IDs, supporting/contradicting/neutral evidence for hypotheses, unresolved questions, and missing telemetry.
- Include AI assessment and recommendations only if available; label AI-generated interpretations separately from deterministic findings.
- Clearly state uncertainty and that successful authentication or HTTP response codes alone do not prove compromise/exploitation.
- Generate a useful report even when Ollama is unavailable.
- Escape/quote raw log content safely; do not allow log text to masquerade as report instructions or headings.

### Suggested interface
- `GET /api/scans/{scan_id}/incidents/{incident_id}/report.md`, or a client-side export using the existing API data.

### Acceptance criteria
- An existing incident exports a readable `.md` file with evidence IDs traceable to the scan.
- Offline/no-AI export still contains deterministic results and uncertainty notes.
- Reports do not cite nonexistent evidence IDs or present inferred graph edges as observed facts.

## Feature 3 — Scan History / SQLite Persistence

**Priority:** P1

### Goal
Preserve investigations across backend restarts and allow users to reopen prior scans.

### Functional requirements
- Use local SQLite storage for scan metadata, normalized events, alerts, incidents, and investigation results.
- Preserve evidence IDs and relationships on reload; regenerate derived graphs/hypotheses from persisted evidence where practical and deterministic.
- Provide a scan-history list with scan time, source types, event/alert/incident counts, and scan ID.
- Allow reopening a scan and navigating its incidents and evidence.
- Support deleting a scan and associated records; document retention behavior.
- Store sensitive logs locally; avoid placing raw logs in browser storage or routine application logs.
- Ensure transactional writes so failed imports do not leave half-written scans.

### Suggested interface
- `GET /api/scans` (history list)
- `GET /api/scans/{scan_id}` (existing or extended retrieval)
- `DELETE /api/scans/{scan_id}`

### Acceptance criteria
- A scan remains accessible after restarting the backend.
- Its alert/incident/evidence references remain consistent after reload.
- Deleting one scan removes it from history without affecting others.
- A failed database write does not create a misleading completed scan.

## Feature 4 — Realistic Data Evaluation and End-to-End Tests

**Priority:** P1

### Goal
Demonstrate that the pipeline works beyond hand-written demonstration samples and quantify its limitations.

### Functional requirements
- Maintain three test groups: synthetic regression samples, externally sourced security logs (with provenance/license documented), and controlled lab scenarios.
- Include benign traffic, malformed logs, timestamp/time-zone edge cases, duplicate/out-of-order records, NAT/shared-IP ambiguity, and prompt-injection strings inside logs.
- Add an end-to-end test for `import → parse → detect → correlate → graph → hypotheses → investigate → export`.
- Track parser success rate, runtime/latency, and evidence-reference validity.
- Measure detection precision/recall and incident grouping quality **only on labeled data**; otherwise report descriptive counts or manually reviewed outcomes.
- Record test environment, sample sizes, dataset sources, expected outcomes, and reproducible commands.
- Verify that missing telemetry remains labeled unknown and that read-only tool restrictions hold.

### Suggested deliverables
- `tests/` integration cases and fixtures.
- `docs/evaluation.md` with methodology, results, limitations, and reproduction steps.

### Acceptance criteria
- Automated tests cover one full user workflow and at least one misleading/non-attack scenario.
- All cited evidence IDs resolve to real records.
- Evaluation claims distinguish measured results from future targets; test suite runs with Ollama disabled.

## Feature 5 — Dashboard Investigation Workflow

**Priority:** P2

### Goal
Make the existing views work as a coherent, incident-centered analyst experience.

### Functional requirements
- Display a scan overview and an incident list with severity, time range, source, and alert count.
- Selecting an incident opens its timeline, evidence graph, hypotheses, and investigation controls in a consistent context.
- Clicking an event, alert, or evidence reference opens a detail panel with normalized fields and raw log where authorized.
- Distinguish **observed** and **inferred** graph edges visually and textually.
- Show supporting, contradicting, neutral, and missing evidence for each hypothesis; do not imply hypothesis confidence is a calibrated compromise probability.
- Allow the analyst to select an available investigation question and run bounded read-only queries; show tool budget, loading/error states, and stopping reason.
- Provide a report export action and graceful fallback when Ollama is offline.
- Ensure the layout remains usable on common laptop/desktop viewport sizes and handles empty states.

### Acceptance criteria
- A user can navigate from a new scan to one incident, inspect a cited raw log, compare hypotheses, run an allowed investigation, and export a report without manually calling APIs.
- No view silently upgrades an inferred relationship into a fact.
- Missing evidence and unavailable AI are clearly communicated.

## Recommended Delivery Order

1. **P0:** Custom Log Upload / Import
2. **P0:** Incident Report Export
3. **P1:** Scan History / SQLite Persistence
4. **P1:** Realistic Data Evaluation and End-to-End Tests
5. **P2:** Dashboard Investigation Workflow

Dashboard refinements can be implemented incrementally alongside the other features. Defer live streaming, multi-host collectors, automatic remediation, new detector families, and ASUS hardware acceleration until after the initial MVP.

## MVP Definition of Done

A user can upload their own SSH/Nginx logs, receive deterministic alerts and correlated incidents, inspect the evidence graph and competing hypotheses, run bounded read-only investigation (with or without an LLM), export an evidence-backed Markdown report, and later reopen the saved scan. This workflow has reproducible end-to-end tests and documented limitations.
