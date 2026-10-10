# AI Security Log Copilot

A local SSH and Nginx log investigation tool. Import your own logs, detect suspicious activity, investigate correlated incidents, inspect evidence, and export Markdown reports. Scans and investigation results are saved in local SQLite so you can reopen them after restarting the backend.

The deterministic backend establishes events, alerts, and observed facts. Optional AI analysis uses Ollama and Qwen to compare explanations and suggest read-only investigation. AI does not change detection results or execute system commands.

```text
SSH / Nginx logs
       |
       v
Parsers -> LogEvent -> Detectors -> SecurityAlert
                                         |
                                         v
                               Incident Correlator
                                         |
                                         v
                        Evidence Graph + Hypotheses
                                         |
                                         v
                         Read-only Investigation
                           + Optional Local AI
                                         |
                                         v
                      Evidence-backed Markdown Report
                              + SQLite History
```

## Quick start

### 1. Install and start the application

Python 3.11 or newer is required. Run these commands from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ./backend
uvicorn app.main:app --app-dir backend --reload
```

Open the dashboard at **http://127.0.0.1:8000**. Interactive API documentation is available at **http://127.0.0.1:8000/docs**.

If the virtual environment already exists, update dependencies and restart the backend:

```sh
.venv/bin/pip install -e ./backend
.venv/bin/uvicorn app.main:app --app-dir backend --reload
```

Stop an existing Uvicorn process with **Ctrl+C** before starting its replacement. After updating the application, refresh the browser with **Ctrl+Shift+R** to load the current interface.

Ollama is optional. Imports, detection, evidence graphs, hypotheses, read-only queries, history, and report exports work without it.

### 2. Enable optional AI analysis

Install Ollama separately, then download the model:

```sh
ollama pull qwen3:4b
```

If Ollama is not already running, start it in a separate terminal:

```sh
ollama serve
```

The default endpoint is `http://127.0.0.1:11434`. Leave Ollama running alongside the application. The dashboard displays whether the configured model is available.

### 3. Try the demonstration

1. In **Log sample**, select **Cross-source · Web reconnaissance → SSH suspicious authentication**.
2. Leave **Use AI** unchecked and click **Detect and analyze**.
3. Expect **10 events, 3 alerts, and 1 Critical incident**.
4. Select the incident, inspect its timeline and evidence, and compare the three hypotheses.
5. Click **Read-only investigation (no AI)** to answer questions using the imported snapshot.
6. Click **Download Markdown** to export the report.
7. If Ollama is ready, click **Compare hypotheses with AI** for an English AI assessment.

The sample records four sensitive-path probes, five failed SSH authentications for `admin`, and a successful authentication from the same IP. **Critical indicates investigation priority, not confirmed compromise.** The successful authentication may be legitimate; the sample has no post-login process, privilege-escalation, data-access, or exfiltration evidence.

## Dashboard operating guide

### Import your own logs

1. Under **Import local logs**, click **Choose log files** and select one or more local files.
2. For each file, explicitly select **SSH authentication** or **Nginx combined access**. The application does not inspect file contents to automatically determine the format.
3. Set **SSH year** to the year the SSH logs were recorded. Traditional SSH syslog timestamps omit the year and timezone. The host timezone is configured through `LOG_TIMEZONE`; Nginx entries use their own year and timezone offset.
4. Leave **Use AI** unchecked for an initial deterministic scan, then click **Import and detect**. If checked, AI analysis is included in the scan request.
5. Review the per-file feedback: total lines, accepted lines, skipped lines, duplicate lines, and diagnostics with line numbers where available.

Valid records remain usable when other lines or files are malformed, empty, or incorrectly encoded. Each file exposes up to 100 diagnostics and reports how many additional diagnostics were omitted. If no events can be parsed, the request fails and no completed scan is added to history. Size and file-line limits reject the import; individual overlong lines are skipped with diagnostics.

For a reproducible upload demonstration, select both files below:

| File | Log type | SSH year |
| --- | --- | --- |
| `samples/scenarios/multi_stage_access.log` | Nginx combined access | Not applicable |
| `samples/scenarios/multi_stage_auth.log` | SSH authentication | `2026` |

The expected result is **10 events, 3 alerts, and 1 incident**. Combined logs must belong to the same host or analysis scope and use consistent timestamps. Import different hosts or different SSH years in separate scans; SSH files in one request share the configured year and host timezone.

### Select an incident and inspect evidence

- **Current scan** shows the scan ID, creation time, unique event count, alert count, incident count, and removed duplicates.
- **Rule alerts** supports searching and filtering. Select an alert to view its summary, normalized fields, associated raw logs, and suggested checks.
- In **Incident list and timeline**, click **Select incident**. Its timeline, hypotheses, graph scope, report link, and saved AI assessment share the selected incident context.
- Click an evidence ID, event node, alert node, or incident node to inspect the original evidence. The detail dialog shows normalized fields and raw logs where present.
- Alert status controls are **page-local**. Marking an alert as resolved does not persist that status to SQLite.

No alerts means no incident or attack hypotheses are created. Parsing results and the saved scan remain available.

### Explore the graph and competing hypotheses

The **Incident Evidence Graph** distinguishes recorded relationships from inference:

| Representation | Meaning |
| --- | --- |
| Solid blue edge | Observed or recorded relationship |
| Dashed orange edge | Unverified inferred relationship |
| Green highlight | Evidence supporting the selected hypothesis |
| Red highlight | Evidence contradicting the selected hypothesis |
| Gray highlight | Neutral evidence |

Select a hypothesis heading to highlight its evidence. Use **Scope**, **Show event nodes**, **Show inferred edges**, and **Zoom** to adjust the graph. **Clear hypothesis focus** removes the overlay. Event nodes are hidden by default for readability; enabling them shows the demonstration's full 20-node graph.

The demonstration compares:

- **H1:** possible related activity by a single attacker.
- **H2:** separate activities behind a shared IP or NAT.
- **H3:** a legitimate login following attack attempts.

Each hypothesis separates supporting, contradicting, neutral, and missing evidence. Observed facts are established by the backend; model explanations are labeled as inference. H2 has no direct NAT attribution evidence. SSH/Nginx logs alone cannot establish whether the successful login in H1/H3 belonged to an attacker or the account owner.

Support scores are **uncalibrated evidence-support measures**, not compromise probabilities, and need not sum to 1. The current AI score ceilings for H1, H2, and H3 are 0.65, 0.35, and 0.55 respectively. These are conservative implementation limits, not statistical estimates.

`CONTAINS` denotes rule-generated group membership. `FOLLOWED_BY` denotes time order. Neither establishes causation or confirms a single attack campaign.

### Run read-only investigation

1. Select an incident.
2. Set **Tool budget this round** to a value from `0` to `12` (default: `4`).
3. Click **Read-only investigation (no AI)** to investigate available questions, or click a question's **Read-only query** button to query that question with a budget of one call.
4. Review the answers, cited evidence, truncation notices, tool trace, and **Investigation status**.
5. With Ollama available, click **Compare hypotheses with AI**. AI can prioritize existing answerable questions and compare the supplied explanations.

Each request runs at most one bounded tool-query round. Failed queries also consume the budget. Already answered questions are not queried again. The demonstration has three answerable questions; budget `4` checks them and stops because the remaining questions require unavailable telemetry. Set budget `1` on a fresh scan to demonstrate stopping at the budget limit.

Additional query results become observed facts and neutral evidence. They do not automatically confirm malicious activity or legitimate login. Empty results describe only this scan and do not establish the absence of activity on the real host.

### Export a report

Click **Download Markdown** beside an incident or in its investigation controls.

The report includes incident metadata, affected IPs/accounts, timeline, associated alerts, observed facts, evidence IDs, competing hypotheses, unresolved questions, missing telemetry, and an evidence appendix. AI assessment and recommendations are included when available and labeled separately as model-generated inference.

Reports work without Ollama. Log strings are quoted as data so they cannot masquerade as report headings or instructions. Downloaded reports contain raw evidence and should be handled accordingly.

### Reopen or delete a saved scan

- Under **Scan history**, click **Open** to restore a scan, its answered questions, and available AI results. Reopening does not rerun detection or call the model.
- After a backend restart, the dashboard opens the latest saved scan. If history is empty, the first page load creates the cross-source demonstration scan.
- Click **Refresh** or **Load more** to update or browse history.
- Click **Delete**, then **Delete scan** in the confirmation dialog, to remove one scan and its associated evidence and investigation records. Other scans are retained.

## Configuration

Set environment variables before starting the backend.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama endpoint reachable from the backend |
| `OLLAMA_MODEL` | `qwen3:4b` | Installed model used for structured analysis |
| `OLLAMA_TIMEOUT` | `300` | Timeout in seconds for each model request |
| `LOG_TIMEZONE` | `Asia/Taipei` | Host timezone for SSH timestamps without an offset |
| `COPILOT_DB_PATH` | `data/copilot.sqlite3` | Local SQLite database path |
| `UPLOAD_MAX_FILES` | `8` | Maximum files per upload |
| `UPLOAD_MAX_FILE_BYTES` | `2097152` | Maximum size per file: 2 MiB |
| `UPLOAD_MAX_TOTAL_BYTES` | `8388608` | Maximum combined file size: 8 MiB |
| `UPLOAD_MAX_LINES` | `10000` | Maximum lines per file; exceeding it rejects the import |
| `UPLOAD_MAX_LINE_BYTES` | `16384` | Maximum bytes per line; longer lines are skipped |

For example, to interpret SSH logs recorded in UTC:

```sh
LOG_TIMEZONE=UTC .venv/bin/uvicorn app.main:app --app-dir backend --reload
```

Built-in SSH samples use year `2026`. Uploads use the year specified by the analyst; the default is the current year. Nginx timestamps include their own year and offset.

## Supported formats and detection rules

Uploads accept UTF-8 and UTF-8 BOM text. Supported formats are traditional OpenSSH syslog authentication entries and Nginx **combined** access logs.

- SSH parsing covers `Failed password` and `Accepted password`, `Accepted publickey`, or `Accepted keyboard-interactive/pam` entries.
- Other SSH operational messages are reported as skipped. Compressed `message repeated N times` records are not expanded into N independent events, which can undercount attempts.
- Repeated records within a scan are deduplicated by normalized event ID so duplicate evidence does not inflate thresholds. Per-file accepted-line counts and scan-wide duplicate counts are reported separately.

| Rule | Current behavior |
| --- | --- |
| SSH brute force | At least five failed authentications from one IP within 60 seconds |
| Suspicious login | Successful authentication from the same IP and account after at least five failures in the preceding 10 minutes; failures at the exact success timestamp do not count as prior failures |
| SQLi attempt | Decoded request patterns such as UNION SELECT, equal-value comparisons, delay functions, information_schema, destructive SQL, or a quote followed by an SQL comment; a plain `--` string alone does not trigger an alert |
| XSS attempt | Script tags, event handlers, or javascript URLs; ordinary image tags or mentions of script/javascript alone do not trigger an alert |
| Web enumeration | At least four sensitive-path requests from one IP within 60 seconds, covering three distinct paths and including at least two HTTP 404 responses; a single `/.env` request does not trigger enumeration |
| Incident correlation | Group by IP and evidence time with a maximum 10-minute span, preventing indefinite chaining; Critical requires ordered web enumeration, at least five SSH failures for the login account, and suspicious successful authentication |

Other incidents retain the highest associated alert severity. An IP may be shared through NAT or a proxy. SQLi/XSS alerts indicate attempts; HTTP 200 alone does not prove exploitation.

Sample directories:

- `samples/ssh/`: SSH samples.
- `samples/`: Nginx samples.
- `samples/scenarios/`: combined SSH/Nginx scenarios.

The legacy `ssh:compromised_login.log` produces two brute-force alerts under the strict account-matching rule. The successful `deploy` login has fewer than five preceding failures for that account; failures for other accounts cannot establish credential guessing against `deploy`.

## AI behavior and language

AI receives the focused incident's observed facts, graph overview, competing hypotheses, and investigation questions. `raw_log` is not sent to the model. Normalized IPs, account names, and request targets remain untrusted data.

The interface and application-generated reports use English. Ollama's analysis and question-selection prompts explicitly require English human-readable output. The backend checks all analysis text fields for Chinese/CJK prose, permitting original evidence identifiers; if necessary, it requests one English rewrite. If the rewrite still fails the language check, the AI result is hidden and an English error is shown. Deterministic findings remain available.

A first incident investigation may use a planning request followed by a comparison request. An English correction can add one model request. Each request has its own timeout. Earlier CPU measurements took approximately six minutes for a complete AI investigation; this is hardware-dependent and is not a benchmark for the current English-output changes. Running read-only queries first can avoid the planning request.

Previously saved application labels are refreshed for English presentation without changing evidence IDs or alert verdicts. Older non-English AI prose is retained locally but is not displayed as an English assessment. Click **Compare hypotheses with AI** to regenerate it. Original logs, filenames, account names, and evidence values retain their original text. The operating system controls the language of its native file-selection dialog.

After updating, restart the backend and force-refresh the browser. Versioned asset URLs and `Cache-Control: no-store` help prevent stale interface text.

### Read-only tools

All tools query the **current scan snapshot**:

| Tool | Purpose |
| --- | --- |
| `search_events` | Filter events by source IP, account, and timezone-aware time bounds |
| `get_user_logins` | Retrieve successful authentications for a specified account |
| `get_related_alerts` | Retrieve alerts for a specified source IP |
| `get_incident_timeline` | Retrieve an incident's recorded timeline |

Tools use an allowlist and do not accept arbitrary file paths, shell commands, or system-changing operations. The backend supplies questions and fixed tool arguments; AI can select existing `question_ids` but cannot create tools or arbitrary arguments.

Queries return at most 100 records and include `total` and `truncated`. Model-selected calls are marked `origin: model`; backend-selected calls are marked `origin: rule`. If a model skips questions or supplies an invalid plan, the backend uses its verified question order.

Final analysis uses an Ollama JSON schema and Pydantic validation. The following is an illustrative structure; the IDs are placeholders:

```json
{
  "summary": "Authentication attempts require investigation; compromise is unconfirmed.",
  "assessment": [{"text": "Repeated failures appear in the evidence.", "evidence_ids": ["SSH-..."]}],
  "recommendations": [{"text": "Compare activity with account owner records.", "evidence_ids": ["INC-..."]}],
  "missing_evidence": ["Post-login process telemetry is missing."],
  "confidence": 0.6,
  "hypothesis_evaluations": [{
    "hypothesis_id": "HYP-...",
    "status": "plausible",
    "confidence": 0.55,
    "inference": "This explanation fits some evidence, but operator identity remains unknown.",
    "evidence_ids": ["SSH-..."],
    "graph_edge_ids": ["EDGE-..."]
  }]
}
```

Claims and comparisons must reference real evidence. Hypothesis IDs and graph-edge references are checked. AI cannot create or modify alerts or the graph, and insufficient attribution prevents definitive conclusions. Invalid formats or references hide the result. Non-read-only recommendations are conservatively filtered; if none remain, a default read-only suggestion is shown with an `ai_warnings` notice.

These checks are not a proof of semantic correctness. Human review is still required. Analysis confidence is the model's self-rating of completeness; hypothesis confidence and inferred-edge confidence describe evidence or rule support. None is statistically calibrated or a compromise probability.

Implementation references: [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs), [Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling), and [Qwen3](https://qwenlm.github.io/blog/qwen3/). The client sets `think=false` and includes `/no_think` in its requests.

## Storage and retention

SQLite stores scan metadata, alerts, incidents, hypotheses, and investigation results as JSON in `scans`. The `events` table stores normalized events and their raw log lines, linked to the scan with cascading deletion. Writes are transactional, and scans are published only after a successful commit. Graphs are reconstructed from persisted evidence on reload.

There is no automatic expiry: scans remain until deleted. The `data/` directory is excluded from Git. Original uploaded files are not separately retained; accepted lines are stored as evidence, while skipped lines retain diagnostics rather than their raw content. Logs are not placed in browser storage or routine application logs.

SQLite is a local plaintext file, created with owner-only read/write permissions. Deletion removes database records logically; it does not guarantee erasure from backups or residual disk storage. Exported reports also contain original evidence.

This MVP is a single-user local service. Keep the default `127.0.0.1` binding and use one Uvicorn worker; multiple workers can have conflicting investigation caches. Memory caches up to 32 scans, while SQLite preserves saved scans across reloads and restarts. There is no multi-user authorization or cross-host identity management. Future rule changes may affect reconstructed graph relationships, while original evidence IDs remain unchanged.

## API reference

| Method and path | Purpose |
| --- | --- |
| `GET /api/health` | Backend health |
| `GET /api/ollama/status` | Ollama connection and configured-model availability |
| `GET /api/samples` | Available sample identifiers |
| `GET /api/events` | Events from the default SSH sample |
| `GET /api/alerts` | Alerts from the default SSH sample |
| `GET /api/import/config` | Upload limits, default SSH year, and host timezone |
| `POST /api/scan` | Scan bundled samples with optional AI analysis |
| `POST /api/scans/upload` | Import files with matching source types through multipart/form-data |
| `GET /api/scans?limit=20&offset=0` | Paginated history metadata without raw logs |
| `GET /api/scans/{scan_id}` | Reopen a saved scan and its investigation results |
| `DELETE /api/scans/{scan_id}` | Delete one scan and its associated records |
| `GET /api/scans/{scan_id}/graph` | Evidence graph |
| `GET /api/scans/{scan_id}/hypotheses` | Incident hypotheses, facts, questions, and stopping reasons |
| `POST /api/scans/{scan_id}/incidents/{incident_id}/investigate` | Bounded investigation of a selected incident |
| `GET /api/scans/{scan_id}/evidence/{evidence_id}` | Evidence details, including raw logs where present |
| `GET /api/scans/{scan_id}/tools/{tool_name}` | Read-only query with query-string arguments |
| `GET /api/scans/{scan_id}/incidents/{incident_id}/report.md` | Download an incident Markdown report |

### Scan a bundled scenario

```sh
curl -X POST http://127.0.0.1:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"sample":"scenario:multi_stage","with_ai":false}'
```

To combine bundled samples, provide `samples`, which takes precedence over `sample`:

```sh
curl -X POST http://127.0.0.1:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"samples":["ssh:suspicious_login.log","nginx:enumeration.log"],"with_ai":false}'
```

Repeated events are deduplicated. Unrelated timestamps or IPs do not automatically become a multi-stage incident.

### Upload SSH and Nginx files

Provide one `source_types` entry for each `files` entry, in matching order. Optional fields are `ssh_year`, `with_ai`, and `tool_budget`.

```sh
curl -X POST http://127.0.0.1:8000/api/scans/upload \
  -F 'files=@samples/scenarios/multi_stage_access.log' -F 'source_types=nginx' \
  -F 'files=@samples/scenarios/multi_stage_auth.log' -F 'source_types=ssh' \
  -F 'ssh_year=2026' -F 'with_ai=false' -F 'tool_budget=4'
```

The response includes `scan_id`, counts, alerts, incidents, per-file feedback, hypotheses, and optional AI results.

### Investigate and export

Replace `SCAN_ID` and `INCIDENT_ID` below with values returned by a scan or saved history:

```sh
curl 'http://127.0.0.1:8000/api/scans?limit=20&offset=0'
curl 'http://127.0.0.1:8000/api/scans/SCAN_ID/graph'
curl 'http://127.0.0.1:8000/api/scans/SCAN_ID/hypotheses'

curl -X POST 'http://127.0.0.1:8000/api/scans/SCAN_ID/incidents/INCIDENT_ID/investigate' \
  -H 'Content-Type: application/json' \
  -d '{"with_ai":false,"tool_budget":4}'

curl 'http://127.0.0.1:8000/api/scans/SCAN_ID/incidents/INCIDENT_ID/report.md' \
  -o incident.md
```

Set `with_ai` to `true` to include AI comparison. To investigate a specific available question, provide its ID in `question_ids`, for example `{"with_ai":false,"tool_budget":1,"question_ids":["QUESTION_ID"]}`. Use IDs returned by the hypotheses endpoint; do not copy placeholder IDs literally.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Dashboard cannot reach the API | Start Uvicorn from the repository root and open `http://127.0.0.1:8000` |
| Ollama is unavailable | From the environment running Uvicorn, run `curl http://127.0.0.1:11434/api/tags`; confirm Ollama is running and `qwen3:4b` is installed |
| Ollama works on the host but not in a container/sandbox | `127.0.0.1` points to that environment; run the backend on the host or set a reachable `OLLAMA_BASE_URL` |
| Model request times out | Check connectivity and hardware performance; `OLLAMA_TIMEOUT` applies to each request and can be configured before startup |
| Interface still shows old text | Restart the old backend process and force-refresh the browser; regenerate older AI assessments with **Compare hypotheses with AI** |
| HTTP 400 during upload | Check the multipart request and file count |
| HTTP 413 during upload | Reduce file size, combined upload size, or lines per file, or configure the documented limits |
| HTTP 422 during upload | Check source types, UTF-8 encoding, supported log format, SSH year, and per-file diagnostics |
| HTTP 503 while saving | Check database-directory write permissions and available disk space; the operation was not successfully saved |
| Missing multi-stage correlation | Check that the logs share an analysis scope, source IP, account, and compatible year/timezone; stages must satisfy the ordering rules |

## Tests and evaluation

Install development test dependencies:

```sh
.venv/bin/pip install -e './backend[test]'
```

Run the offline test suite and evaluation from the repository root:

```sh
COPILOT_DB_PATH=/tmp/copilot-regression.sqlite3 PYTHONPATH=backend \
  .venv/bin/python -m unittest discover -s backend/tests -v

PYTHONPATH=backend .venv/bin/python scripts/evaluate.py \
  --output /tmp/copilot-evaluation.json

node --check app.js
node --check graph.js
node --check hypotheses.js
```

Optional browser workflow checks require Firefox and permission to start a loopback server. They use a separate temporary profile:

```sh
PYTHONPATH=backend .venv/bin/python scripts/browser_smoke.py
```

To capture controlled local HTTP requests in Nginx combined format:

```sh
.venv/bin/python scripts/collect_lab.py --output /tmp/copilot-lab
```

Upload `/tmp/copilot-lab/access.log` as Nginx to inspect the capture. This script uses a Python HTTP emitter, not an actual Nginx or SSH daemon, and does not establish successful exploitation.

Dataset provenance, methodology, recorded measurements, reproduction commands, and limitations are documented in [docs/evaluation.md](docs/evaluation.md), with machine-readable results in [docs/evaluation-results.json](docs/evaluation-results.json). The methodology document is currently in Traditional Chinese. External Loghub OpenSSH fixtures carry their research/academic-use license in `backend/tests/fixtures/external/LOGHUB_LICENSE`; preserve that notice and the required attribution when using or distributing those fixtures.

Precision/recall claims apply only to labeled fixtures. Unlabeled external logs support descriptive counts, not real-world detection-accuracy claims. Recorded evaluation results predate the latest English-presentation changes and should not be treated as verification of those changes.

## Implementation map

| File | Responsibility |
| --- | --- |
| `backend/app/main.py` | Scan, import, history, investigation, evidence, and report APIs |
| `backend/app/parsers/` | SSH and Nginx parsing |
| `backend/app/detectors/` | Deterministic attack-attempt rules |
| `backend/app/incidents.py` | Incident grouping and timelines |
| `backend/app/intelligence_models.py` | Graph, hypothesis, question, and investigation contracts |
| `backend/app/graph.py` | Deterministic graph with evidence references |
| `backend/app/hypotheses.py` | Hypothesis templates, evidence categories, facts, and questions |
| `backend/app/investigator.py` | Bounded planning, read-only queries, stopping, and AI comparison |
| `backend/app/copilot.py` | Ollama requests, evidence validation, and recommendation filtering |
| `backend/app/importer.py` | Bounded imports and per-line diagnostics |
| `backend/app/storage.py` | SQLite transactions, restore, history, and deletion |
| `backend/app/reports.py` | Evidence-backed Markdown export |
| `backend/app/language.py` | English output policy and presentation checks |
| `backend/app/localization.py` | English presentation of older saved scans |
| `app.js` | Scan/import workflow, incident context, history, and evidence details |
| `graph.js` | SVG graph, filtering, evidence navigation, and hypothesis highlighting |
| `hypotheses.js` | Hypothesis cards, questions, and investigation controls |

## Current limitations

The MVP does not provide live log collection, multi-host attribution, firewall/auditd/process-log ingestion, historical host or login baselines, automatic remediation, or multi-user access control. Imported file boundaries do not establish host identity. Larger full-scan graphs may be slow; incident scope and hidden event nodes improve readability.

SSH/Nginx evidence can describe suspicious attempts and authentication outcomes, but cannot establish operator identity, authorization, post-login activity, or confirmed compromise by itself. Missing telemetry remains unknown.
