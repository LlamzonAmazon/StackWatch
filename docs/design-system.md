# Design system

The visual spec with live specimens is [design-system.html](design-system.html); open it in a browser. Tokens are defined under `:root` in `web/styles.css` and mirrored at the top of the spec. Change tokens in both places.

## Principles

1. **Flat.** Separate content with solid fills and spacing. Use a full-width rule before a container. No borders around content.
2. **Evidence required.** No finding renders without a source link.
3. **Match claim strength.** Solid tags for proven status only. Weaker claims are dot labels.
4. **One primary action per view.** It is the only bone-filled control on the screen.
5. **Machine values are mono.** Versions, IDs, enum values and timestamps use Geist Mono. Prose is Geist.
6. **Motion is functional.** A row opens, a new finding flashes once. Nothing animates without a state change.

## Tokens

| Group | Tokens |
|-------|--------|
| Surface | `--bg #0a0a0b`, `--fill-1 #121214`, `--fill-2 #1a1a1d`, `--fill-3 #26262a`, `--line` |
| Text | `--text #f4f3ef`, `--text-2 #a3a29d`, `--text-3 #6f6e6a` |
| Accent (bone) | `--accent #ece7da`, `--accent-hi`, `--accent-press`, `--accent-ink` |
| Status | `--verify #9b8cff`, `--green #3fb27f`, severity `--sev-critical #e5534b`, `--sev-high #e08b3a`, `--sev-medium #d9b43a`, `--sev-low #5b95d6`, `--sev-unknown` |
| Radius | `--r-ctl 6px`, `--r-tag 4px`, `--r-0` |
| Type | Geist / Geist Mono; `--fs-xs 12px` to `--fs-2xl clamp(30px, 4vw, 46px)` |
| Motion | `--dur-fast 120ms`, `--dur-base 200ms`, `--dur-moderate 280ms`, `--dur-slow 440ms`; `--ease-standard cubic-bezier(0.2,0,0,1)`, `--ease-enter`, `--ease-exit`; `--stagger 40ms` |
| Layout | `--nav-w 232px`, `--insp-w 420px`, `--panel-h 260px` |

Dark only today. A light theme would redefine the surface and text groups.

## Status language

| Kind | Rendering | Values |
|------|-----------|--------|
| Severity | solid tag | critical, high, medium, low, unknown |
| Verification outcome | solid tag (red when exposed, green when clear) | `exposure_verified`, `affected_component_found`, `not_reproduced`, `inconclusive`, `not_run` |
| Match status | dot label | `confirmed_affected_version`, `possible_match`, `not_affected_version`, `needs_review` |
| Confidence | dot label, strongest is a chip | `inferred`, `confirmed_in_repo`, `confirmed_in_runtime` |

## Components covered by the spec

Overview numbers, actions and controls, inventory list, findings and the evidence chain, live activity feed, motion specimens.
