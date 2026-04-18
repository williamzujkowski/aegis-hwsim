# Research index

> **Canonical entry point:** [`INDEX.md`](INDEX.md) — frontmatter, quick stats, validation recipe.
> This file is preserved for back-compat with existing inbound links and lists the same content surfaces.

Nexus-agents-style research tracking for aegis-hwsim. Every external claim in our README, architecture docs, or design decisions should trace back to an entry here.

## What lives here

| File | Purpose |
|------|---------|
| [INDEX.md](INDEX.md) | **Canonical index** — topology, status semantics, citation policy, triage cadence. |
| [prior-art.md](prior-art.md) | Tool-by-tool survey of adjacent projects (chipsec, fwts, LAVA, openQA, fwupd CI, ...). Why each is / isn't overlap. |
| [recent-projects.md](recent-projects.md) | 2025/2026 delta-scan: new projects, evolved tooling, and explicit non-findings. Tracks what's *moved* since the initial prior-art pass. |
| [arxiv-papers.md](arxiv-papers.md) | Verified academic papers (arxiv ID or DOI) tied to aegis-hwsim's scope: SoK on UEFI security, boot integrity surveys, vTPM attestation, UEFI memory forensics, EDK-2 fuzzing harness design. |
| [gotchas.md](gotchas.md) | Confirmed limitations from the community — what has broken for others trying similar approaches, with citations. |
| [audience.md](audience.md) | Target-user segments and why each would adopt. Used for first-adopter outreach planning. |
| [registry/](registry/) | Machine-readable YAML registry: `sources.yaml` (14 tools), `papers.yaml` (5 papers), `projects.yaml` (5 projects), `SCHEMA.json` (validator). |

## Source-citation policy

Matches [aegis-boot](https://github.com/williamzujkowski/aegis-boot)'s `compat` DB policy: **verified outcomes only**. Each claim must link to:

- A primary source (project README, upstream documentation, official spec)
- Or a secondary source that explicitly cites the primary (Black Hat talk with cited papers, LWN article with linked mailing-list posts)
- Or a first-person observation with a reproducible repro command

"X said at a conference" without a recoverable artifact is not acceptable — someone has to be able to verify the claim without taking our word for it.

## Triage status

The initial survey (2026-04-18) was a quick pass. Re-run when:

- A new first-adopter files an issue referencing a tool we didn't catalog
- A major release lands in any of the catalogued projects (annual)
- Before cutting v1.0.0 of aegis-hwsim (gate)
