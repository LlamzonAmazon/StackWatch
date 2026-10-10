# Outstanding items

Ordered by priority for a portfolio project. Numbers are stable IDs; do not renumber when an item closes. Start with 1 and 4: lock the API down, then build the intel cross-reference so the product matches the pitch.

Status: `open`, `partial`, `done`.

## Security (fix first)

| # | Item | Status |
|---|------|--------|
| 1 | **No authentication on the API.** Anyone who can reach a hosted instance can make the server scan and fetch arbitrary domains: an open, SSRF-capable proxy. Add auth and rate limiting before any public link goes on a resume. Check whether a teammate's hosted instance from the event is still running. See audit H-3 and M-5. | done: API key on every `/api` route except health, fail-closed, plus per-IP rate limiting on scan and fetch routes (`app/auth.py`). Still check the teammate's hosted instance. |
| 2 | **Hardcoded ClickHouse password** in `scripts/schema.sql`. | done: the runtime user is now created by `scripts/apply_schema.py` from `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD`, and the old value never entered this repo's history. Rotate it anywhere it was used. |
| 3 | **Review the pentest report and security audit before going public.** | done: the Juice Shop pentest report (exploit write-ups, run-specific) was dropped in the migration. The self-audit is kept as [security-audit.md](security-audit.md); its open findings are public by design. |

Related hardening done during migration: ClickHouse ports and the documented uvicorn command now bind to `127.0.0.1` (partial fix for audit H-4; the `default` user is still passwordless inside the container).

## Unfinished features

| # | Item | Status |
|---|------|--------|
| 4 | **Threat-intel cross-reference.** CISA KEV, NVD matched by CPE, and EPSS scoring were never built. Exposure shows OSV results and configuration findings only. Biggest gap against the pitch. | partial: CISA KEV and EPSS are joined to OSV advisories by CVE alias ([D10](design-decisions.md)). Still open: NVD matched by CPE (needs item 5's versions). |
| 5 | **Version fingerprinting.** The stack summary for public domains rarely captures versions, and item 4 needs them for CPE matching. | open |
| 6 | **Senso.** Built (`app/integrations/senso.py`) but never verified against a real key. | open |
| 7 | **Configuration findings are invisible to the attack-chain correlator.** They render on the board but are not graph nodes. | open |
| 8 | **Domains are not monitored.** The watcher skips public targets, so continuous monitoring is only true for repositories. | open |
| 9 | **Runtime checks are unreachable from the UI.** Repository mode only runs Semgrep; live-deployment checks need an `owned_deployment` target the UI cannot create. | open |
| 10 | **State is lost on restart.** Live knowledge bases, deep-scan results and in-flight runs live in memory. | open |

## Quality

| # | Item | Status |
|---|------|--------|
| 11 | **No CI**, pre-existing ruff errors, and a Python version mismatch (an old local venv was 3.11; `pyproject.toml` requires 3.12). | done: ruff is clean under an explicit rule selection in `pyproject.toml`, `.github/workflows/ci.yml` runs ruff and pytest on Python 3.12 with SHA-pinned actions and read-only permissions, and `pytest`/`ruff` moved to the `dev` extra. |
| 12 | **`config/demo.yaml` is rewritten at runtime** (demo replay and `setup_demo.sh`), so it always shows as modified. Move runtime state out of it. See audit L-3. | open |
| 13 | **Dead code:** the original OpenAI explanation module (`app/intel/explain.py`) is never called. Delete it or route it through the shared LLM client in `app/agent/llm.py`. | open |
| 14 | **No agent evaluation.** Run live on about 3 domains only. A 10 to 20 domain eval set would give fact precision, rejection rate and latency (about 47s now). | open |
| 15 | **UI never browser-tested.** Mobile and accessibility unchecked. | open |

## Portfolio packaging

| # | Item | Status |
|---|------|--------|
| 16 | **README rewrite** with an architecture diagram and setup steps. | partial: rewritten with a Mermaid diagram and quickstart during migration. Verify the quickstart from a clean clone. |
| 17 | **Demo assets:** a 2-minute video plus screenshots of the knowledge base and evidence inspector. | open |
| 18 | **Contribution statement:** what is Thomas's versus teammates'. | done: [goals.md](goals.md#contributions). The clean-slate history drops teammates' commits, so this statement is the record. |
| 19 | **Record the outcome of the event.** | open |
