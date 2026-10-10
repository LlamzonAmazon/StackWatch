# Goals

## What StackWatch answers

For a given target, three questions, in order:

1. **What is it running?** A versioned inventory of packages, services and infrastructure, built from lockfiles or from what a public domain serves.
2. **What affects it?** Published advisories that match the inventory, by exact version range.
3. **What is real risk?** Which matches are reachable or verified, ranked by severity, exploitation signals and exposure, each with a source link.

The original pitch: an agent that pulls threat intel from public security sources and puts emerging threats in context for a specific company, based on its stack and exposure.

## Product goals

- **Evidence first.** No finding without a source link and the observation that produced it.
- **Claims match proof.** `present` (version in range), `reachable` (on a route), and `verified` (Semgrep or runtime confirmed) are different statuses and the UI shows them differently.
- **Passive by default.** Public domains get passive recon only. Active checks need an explicit authorization entry.
- **Continuous.** Re-check targets when the inventory or the advisory feed changes, not only on demand.
- **Runs locally.** No paid feeds or hosted LLM required. A local model handles research; matching stays deterministic.

## Non-goals

- Active exploitation or payload delivery against targets that are not authorized.
- Multi-tenant SaaS. A single-operator tool comes first; auth (backlog item 1) is about safe hosting, not tenancy.
- Replacing a full SCA product. Ecosystem coverage is npm first.

## Success criteria

These turn "it works" into numbers for the README and a resume line. Most depend on backlog items 4 and 14.

| Metric | Target | Today |
|--------|--------|-------|
| Agent fact precision on a 10 to 20 domain eval set | measured and published | not measured (about 3 domains run live) |
| End-to-end public-domain scan latency | under 30s p50 | about 47s with the agent |
| Findings carrying KEV / EPSS context | every CVE-backed finding | 0, not built |
| Test suite | green in CI | 378 pass locally, no CI |

## Portfolio goals

- A public repo that reads as a coherent product: README with architecture, setup that works from a clean clone, docs that explain decisions.
- A 2-minute demo video and screenshots of the knowledge base and evidence inspector.
- An honest contribution statement (below).

## Contributions

StackWatch began as a four-person build in October 2026. Pillar ownership at kickoff: discovery (Fuad), intelligence and matching (Thomas), verification (Sid), product and monitoring (Andres). From the original commit history:

- **Sid:** the first end-to-end Python pipeline (orchestrator, intel, dashboard), the Semgrep verification pillar and its Juice Shop rules, the deep-scan pillar (`app/scanner`), and the security hardening and test expansion behind the self-audit.
- **Andres:** repository setup and the original Next.js product shell (since removed).
- **Thomas:** the design and motion system and the console UI rebuild, public-domain recon (DNS, mail security, RDAP, TLS, CT, scoped scrape, SPA bundles), the knowledge base, the grounded research agent, configuration (posture) findings, Senso ingest, and the integration and merge work across pillars.
- TODO (Thomas): confirm authorship of the skills, exposure graph and severity/novelty correlator (`app/skills`, `app/correlate`), committed by Thomas at handoff.
- TODO (Thomas): Fuad's discovery work has no commits under his name; confirm what landed.

Work after the clean-slate migration is Thomas's unless noted in the commit.
