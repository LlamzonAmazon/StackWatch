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

StackWatch began as a team build in October 2026.

- **Thomas Llamzon:** agent infrastructure and the full stack: the pipeline, exposure graph and correlator, recon and knowledge base, the grounded research agent, the API, the console UI and the design system.
- **Andres:** the agent's web scraping.
- **Sid:** the adversarial pentesting functionality (deep scan, endpoint enumeration, attack-chain patterns).

Work after the clean-slate migration is Thomas's unless noted in the commit.
