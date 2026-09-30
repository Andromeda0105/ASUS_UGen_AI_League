# AI Security Log Copilot

Local-first prototype for detecting SSH and Nginx attacks and using a local Ollama model to explain the results. Detection is deterministic; Qwen explains structured events and does not decide whether the detector should alert.

## Start the app

Python 3.11+ and Ollama are required. `qwen3:4b` should already be pulled.

Terminal 1: start Ollama if it is not already running:

```sh
ollama serve
```

Terminal 2: from the repository root, set up and start the API and dashboard:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ./backend
uvicorn app.main:app --app-dir backend --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The dashboard shows whether the local model is reachable. To check Ollama separately, run `ollama list` and confirm `qwen3:4b` is present. API documentation is at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

If Ollama listens somewhere other than `http://127.0.0.1:11434`, set `OLLAMA_BASE_URL`. You can also choose another installed model with `OLLAMA_MODEL`; the default is `qwen3:4b`.

### If the dashboard says Ollama is unreachable

Run `curl http://127.0.0.1:11434/api/tags` **from the same environment that runs Uvicorn**. If Ollama is reachable from your desktop terminal but not from a container or sandbox, that environment has its own `127.0.0.1`. The simplest fix is to run Uvicorn in a normal host terminal alongside Ollama. For a container setup, configure `OLLAMA_BASE_URL` to the host address that the container can reach; Ollama must also listen on that interface.

The scan error now distinguishes a connection failure from an Ollama request timeout. The default model timeout is 180 seconds; increase it with `OLLAMA_TIMEOUT` if generation takes longer.

## Use the dashboard

1. Choose an SSH or Nginx sample from the selector.
2. Click **偵測並分析**.
3. Review the deterministic alerts in the table and click an alert for its evidence, parsed request details, and raw log line.
4. Read the Copilot analysis below the table. If Ollama is offline, rule-based alerts still appear; start Ollama and click the button again to retry.

Included scenarios under `samples/ssh/`:

- `normal.log`: ordinary SSH activity with an isolated failed login; expected to produce no alert.
- `bruteforce.log`: repeated failed authentication from one source.
- `suspicious_login.log`: repeated failures followed by a successful login from the same source.
- `compromised_login.log`: two attack sources, including a brute-force attempt followed by a successful login.

Included Nginx scenarios under `samples/`:

- `normal.log`: ordinary requests; expected to produce no alert.
- `sqli.log`: SQL injection attempts in query parameters.
- `xss.log`: encoded script and event-handler payload attempts.
- `enumeration.log`: repeated probes for sensitive files and admin paths.
- `mix.log`: enumeration, SQLi, and XSS activity in one access log.

## What the SSH detector flags

- **SSH brute force:** five or more failures from one source within a 60 second sliding window.
- **Possible account compromise:** a successful login from a source with at least five failed attempts in the preceding 10 minutes.

The second alert means the sequence warrants investigation; it does not confirm that an account was compromised. The Copilot receives normalized timestamps, event types, IPs, usernames, and detector evidence. Raw log lines stay in the local app and are not included in the Ollama prompt. Recommendations are advisory; the app does not block IPs or run commands.

## Nginx detection

- **SQLi attempt:** stateless pattern matching over URL decoded request targets, including tautologies, `UNION SELECT`, SQL comments, and common time-delay functions.
- **XSS attempt:** stateless pattern matching for script/HTML tags, event handlers, and `javascript:` payloads after URL decoding.
- **Web enumeration:** groups requests by source IP and a 60-second sliding window; alerts on at least four sensitive-path requests across three distinct paths, with at least two HTTP 404 responses.

SQLi and XSS alerts describe attempts, not successful exploitation. Enumeration is correlated by source and time window. All three detector outputs use the same `SecurityAlert` and `ScanResult` models as SSH and are sent together to the local Copilot.

## API

- `GET /api/health` — backend status.
- `GET /api/ollama/status` — local Ollama and configured model status.
- `GET /api/samples` — available SSH sample files.
- `GET /api/events` and `GET /api/alerts` — default SSH compromised-login scenario.
- `POST /api/scan` — scan any listed sample and, by default, request a local AI analysis. Example: `{"sample":"nginx:mix.log","with_ai":true}`. Set `with_ai` to `false` to run detection without Ollama.

This prototype scans the bundled samples on demand. It does not tail live SSH/Nginx logs, persist status changes, or parse firewall logs.

The parsed event count and alert table update from the selected sample. The activity and threat distribution charts are still visual placeholders and are labeled as such in the dashboard.

Run the parser, detector, shared API-flow, and Copilot-output tests with:

```sh
PYTHONPATH=backend .venv/bin/python -m unittest discover -s backend/tests -v
```
