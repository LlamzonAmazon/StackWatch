# Design decisions

Append-only log. Each entry: the decision, what drove it, and the alternatives considered. Supersede an entry with a new one rather than editing it.

## D1. Deterministic matching; the LLM never decides a finding

**Decision:** advisory matching is semver range logic against OSV data. The LLM only does research and narration.
**Why:** a finding must be reproducible and defensible. An LLM match cannot be audited and drifts between runs.
**Alternatives:** LLM-based relevance scoring (rejected: unexplainable false positives).

## D2. Quote-grounded research agent on a local model

**Decision:** the research agent runs on a local OpenAI-compatible endpoint (Ollama, Ministral 8B) and must attach a verbatim quote from a fetched page to every fact.
**Why:** zero marginal cost, no target data sent to a third party, and grounding turns hallucination into a measurable rejection rate.
**Alternatives:** hosted GPT-class model (cost and data egress), ungrounded extraction (unverifiable).

## D3. Skills feed a graph; only the correlator emits findings

**Decision:** each skill contributes nodes and edges to an exposure graph. Findings come from joining the graph.
**Why:** reach and attack chains need cross-pillar context (a vulnerable package is only urgent if it sits on a route). Independent skills also fail in isolation.
**Alternatives:** per-pillar findings merged at the end (could not express reach or chains).

## D4. Claim strength is a first-class status

**Decision:** `present`, `reachable` and `verified` are distinct, and the UI renders proven status as solid tags and weaker claims as dot labels.
**Why:** most SCA noise comes from treating "version in range" as "exploitable".

## D5. Active checks require an authorization entry

**Decision:** Semgrep and runtime checks run only for targets in `config/demo.yaml` `authorized_targets`, pinned to a repo path and host allowlist. Public domains are passive only.
**Why:** scanning infrastructure you do not own is a legal and ethical problem. The allowlist makes the boundary explicit and testable.
**Follow-up:** runtime state should move out of this file (backlog item 12).

## D6. ClickHouse as the system of record

**Decision:** runs, events, advisories and knowledge go to ClickHouse MergeTree tables.
**Why:** the workload is append-heavy event history with analytical reads (diffs between runs, counts over time).
**Alternatives:** SQLite or Postgres (simpler to operate, weaker for event analytics). Revisit if deployment cost matters more than analytics.

## D7. Python FastAPI over the Next.js prototype

**Decision:** the FastAPI backend with a static console replaced the Next.js scaffold, which was deleted.
**Why:** the security tooling (Semgrep, dnspython, OSV parsing) is Python-native, and two stacks doubled maintenance.

## D8. Vanilla JS console, no build step

**Decision:** `web/` is plain HTML, CSS and JS served by FastAPI.
**Why:** one process, no bundler, and the UI is a read-mostly console.
**Revisit:** if the UI grows stateful views beyond the console.

## D9. Clean-slate repository (2026-10-09)

**Decision:** StackWatch continues in a new repository with fresh history, migrated from the event repo's tracked files only.
**Why:** a coherent public history for the portfolio, and the hardcoded database password never enters the new history.
**Cost:** teammates' commits are not carried over; attribution lives in [goals.md](goals.md#contributions). Dropped: the Juice Shop pentest report, runtime data, local tool binaries and the untracked demo targets.
