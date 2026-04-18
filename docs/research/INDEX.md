---
title: aegis-hwsim research index
description: Structured index of adjacent tools, academic papers, and recent projects that informed aegis-hwsim's design or scope.
tier: 1
keywords: [research, prior-art, qemu, ovmf, swtpm, secureboot, uefi, persona, registry]
last_reviewed: '2026-04-18'
---

# aegis-hwsim research index

Nexus-agents-style research tracking for [aegis-hwsim](https://github.com/williamzujkowski/aegis-hwsim). Two layers:

- **Narrative** — long-form Markdown analysis. Use when you want to understand *why* a tool was catalogued or *what* the academic landscape looks like.
- **Registry** — machine-readable YAML keyed off [`SCHEMA.json`](registry/SCHEMA.json). Use when you want to programmatically enumerate adjacent tools (link-checkers, README generators, CHANGELOG emitters, fitness audits).

Every external claim in our README, ARCHITECTURE.md, or design decisions should trace back to an entry here.

## Topology

```
docs/research/
├── INDEX.md              ← you are here (entry point)
├── README.md             ← legacy index — points here
├── prior-art.md          ← narrative survey of adjacent tools
├── arxiv-papers.md       ← narrative survey of academic papers
├── recent-projects.md    ← 2025/2026 delta-scan
├── gotchas.md            ← confirmed failure modes (with citations)
├── audience.md           ← target-user segments + adoption rationale
└── registry/
    ├── SCHEMA.json       ← JSON Schema 2020-12 for the *.yaml files below
    ├── sources.yaml      ← 14 adjacent tools (chipsec, fwts, LAVA, openQA, ...)
    ├── papers.yaml       ← 5 academic papers (arXiv / DOI)
    └── projects.yaml     ← 5 recent projects (qemu-tpm-measurement, intel/tsffs, ...)
```

## Quick stats

| Layer       | Count | Latest review |
| ----------- | ----: | ------------- |
| Sources     | 14    | 2026-04-18    |
| Papers      | 5     | 2026-04-18    |
| Projects    | 5     | 2026-04-18    |
| Narrative   | 5 docs | 2026-04-18   |

## Source-citation policy

Matches [aegis-boot](https://github.com/williamzujkowski/aegis-boot)'s `compat` DB policy: **verified outcomes only**. Each registry entry must have:

- A working URL (validated at `last_verified_at`)
- A `tie_in` (papers) or `notes` (sources, projects) explaining how it informs aegis-hwsim's design or scope
- A primary source — project README, upstream documentation, official spec, arXiv ID, or DOI
- A `last_verified_at` date so staleness is visible

"X said at a conference" without a recoverable artifact is not acceptable — someone has to be able to verify the claim without taking our word for it.

## Status semantics

| Status     | Meaning                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------- |
| `active`   | Currently relevant; URL works; scope still applies.                                          |
| `stale`    | Needs re-verification — `last_verified_at` is older than 12 months OR upstream has shifted. |
| `archived` | Superseded by another entry, deprecated upstream, or no longer relevant. Kept for history.  |

## Relationship semantics

| Kind                | When to use                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------------- |
| `complementary`     | Different scope, doesn't compete (chipsec audits live; we test emulated). Most catalog rows. |
| `integration-target`| Future code-level integration possible (LAVA job emit, SBAT axis from fwupd plugin).         |
| `reference`         | Read for design ideas, not borrowed code (puzzleos/uefi-dev, Noodles' blog).                 |
| `orthogonal`        | Adjacent in tech stack but unrelated in goal (KernelCI, OSBuild, edk2-SCT).                  |
| `competitor`        | Direct overlap. **Reserved** — no entries qualify as of v0.0.x; see prior-art.md.            |
| `potential-adopter` | Process / community we'd target for first-adopter outreach (shim-review).                    |

## Triage cadence

Re-run the registry verification when:

- A new first-adopter files an issue referencing a tool not in `sources.yaml`
- A major release lands in any catalogued project (annual sweep)
- Before cutting v1.0.0 of aegis-hwsim (release gate)
- Any entry's `last_verified_at` exceeds 12 months → mark as `stale`, re-verify, then update

## Validating registry entries

```bash
# JSON Schema spot-check (requires `check-jsonschema` from the
# python-jsonschema-objects ecosystem):
pipx install check-jsonschema
check-jsonschema --schemafile docs/research/registry/SCHEMA.json \
  docs/research/registry/sources.yaml \
  docs/research/registry/papers.yaml \
  docs/research/registry/projects.yaml
```

A future `aegis-hwsim research-index --verify` subcommand could fold this into the main binary; tracked as a non-blocking improvement.

## Cross-project alignment

aegis-hwsim's research index mirrors the [nexus-agents](https://github.com/williamzujkowski/nexus-agents) pattern: human narrative in Markdown, machine registry in YAML, schema in JSON Schema, frontmatter on the index page. The format is intentionally portable — any downstream consumer that knows nexus-agents' research index can read this one.
