# Infrastructure

Everything runs on one machine today. Nothing is deployed.

## Components

| Component | Choice | Notes |
|-----------|--------|-------|
| App server | FastAPI + uvicorn, Python 3.12 | Serves API and `web/`. Bind to `127.0.0.1:3003` until auth exists. |
| Database | ClickHouse 24.3 via `docker-compose.yml` | Ports bound to localhost. Schema in `scripts/schema.sql`, applied by `scripts/apply_schema.py`. |
| Advisory data | OSV npm corpus | Loaded by `scripts/load_osv_corpus.py`; cached under `data/` (gitignored). |
| Static analysis | Semgrep CLI | Subprocess, argv list, `--metrics=off`. Rules in `rules/`. |
| LLM | Ollama, `ministral-3:8b-instruct-2512-q4_K_M` | Any OpenAI-compatible endpoint works via `LLM_BASE_URL`. Optional. |
| Knowledge search | Senso (optional) | Ingests the knowledge base; spends credits per ingest and search; HTTP 402 when out. Unverified (backlog item 6). |
| Lockfile generation | npm | `--package-lock-only --ignore-scripts`, never installs. |
| Demo target | OWASP Juice Shop v15.0.0 | Cloned into `demo/juice-shop` by `scripts/setup_demo.sh`. |

## Ports

| Port | Service |
|------|---------|
| 3003 | StackWatch API and console |
| 3004 | Optional live Juice Shop for `owned_deployment` checks |
| 8123, 9000 | ClickHouse HTTP and native (localhost only) |
| 11434 | Ollama |

## Configuration

Environment variables, documented in `.env.example`. The app reads the process environment and does not load `.env` itself; export it (`set -a; source .env; set +a`).

| Variable | Purpose |
|----------|---------|
| `CLICKHOUSE_HOST`, `_PORT`, `_DATABASE` | Connection (database defaults to `stackwatch`) |
| `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | Least-privilege runtime user, also created from these by `apply_schema.py` |
| `CLICKHOUSE_ADMIN_USER`, `CLICKHOUSE_ADMIN_PASSWORD` | Used only by `apply_schema.py` |
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, `LLM_ENABLED`, `LLM_MAX_STEPS` | Research agent |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | Legacy explanation module (dead code, backlog item 13) |
| `NVD_API_KEY` | Optional. Raises the NVD rate limit from 5 to 50 requests per 30s; sent as the `apiKey` header only |
| `GITHUB_TOKEN` | Reserved |
| `SENSO_API_KEY`, `SENSO_BASE_URL` | Optional Senso integration |
| `POLL_INTERVAL_SECONDS` | Watcher interval (default 300) |
| `ALLOWED_REPO_ROOTS` | Path-separated roots a repo target may resolve into (default `demo`) |
| `DEMO_MODE`, `CACHE_ONLY` | Demo replay and offline caches (OSV, KEV, EPSS, NVD): no intel request is made |

`config/demo.yaml` holds `authorized_targets`: the only targets that get active verification.

## Enabling Senso

1. Get an org API key from Senso (https://docs.senso.ai/docs/api-keys).
2. Set `SENSO_API_KEY` in `.env`. `SENSO_BASE_URL` defaults to `https://apiv2.senso.ai/api/v1`.
3. Restart and run a public-domain scan. The activity feed shows "Ingested into Senso", and the ask box on the Target tab works once indexing finishes.

## Hosting (not done)

Prerequisites before any public instance: API auth and rate limiting (backlog item 1), persistent run state (item 10), and a password on the ClickHouse `default` user (audit H-4). A small VM or container host with ClickHouse Cloud, and no exposed database port, is the likely shape.
