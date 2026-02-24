# i18n Gap Backlog

This file tracks remaining localization depth gaps after the 2026-02-24 deep docs cleanup.

Last updated: **2026-02-24**.

## Baseline Definition

Gap baseline = top-level English docs set under `docs/*.md` (excluding README/SUMMARY locale variants and legacy `*.vi.md` shims) compared against `docs/i18n/<locale>/`.

## Current Gap Counts

| Locale | Missing top-level docs parity count | Current status |
|---|---:|---|
| `zh-CN` | 34 | Runtime Wave 1 + hub scaffold |
| `ja` | 34 | Runtime Wave 1 + hub scaffold |
| `ru` | 34 | Runtime Wave 1 + hub scaffold |
| `fr` | 34 | Runtime Wave 1 + hub scaffold |
| `vi` | 0 | Full top-level parity |
| `el` | 0 | Full top-level parity |

## What Was Completed in This Wave

- `vi` parity lifted to full top-level coverage by adding localized bridge docs for missing files.
- `el` parity lifted to full top-level coverage by adding localized bridge docs for missing files.
- `zh-CN`/`ja`/`ru`/`fr` received Wave 1 runtime localization bridge docs:
  - `commands-reference.md`
  - `providers-reference.md`
  - `channels-reference.md`
  - `config-reference.md`
  - `operations-runbook.md`
  - `troubleshooting.md`
- Canonical path remained `docs/i18n/<locale>/`.

## Remaining Gaps (Actionable)

For `zh-CN`/`ja`/`ru`/`fr`, Wave 1 runtime docs are now available. Remaining missing set focuses on deeper integrations, governance, and support docs:

- operations/extensions: `network-deployment`, `mattermost-setup`, `nextcloud-talk-setup`, `one-click-bootstrap`
- integrations: `custom-providers`, `zai-glm-setup`, `langgraph-integration`
- governance: `docs-inventory`, `i18n-guide`, `i18n-coverage`, `docs-audit-2026-02-24`
- security/project/hardware support docs and related playbooks

## Proposed Completion Waves

### Wave 1 (high-impact runtime) - Completed on 2026-02-24

For `zh-CN`/`ja`/`ru`/`fr`:

- `commands-reference.md`
- `config-reference.md`
- `troubleshooting.md`
- `operations-runbook.md`
- `providers-reference.md`
- `channels-reference.md`

### Wave 2 (integration + security)

- `custom-providers.md`
- `zai-glm-setup.md`
- `langgraph-integration.md`
- `network-deployment.md`
- `audit-event-schema.md`
- `proxy-agent-playbook.md`
- `mattermost-setup.md`
- `nextcloud-talk-setup.md`

### Wave 3 (governance + snapshots)

- `docs-inventory.md`
- `i18n-guide.md`
- `i18n-coverage.md`
- latest docs/project snapshots and audit snapshots

## Tracking Rules

1. Keep this backlog date-stamped and append updates instead of rewriting historical decisions.
2. When a locale closes a gap wave, update counts and coverage status in `docs/i18n-coverage.md`.
3. Keep locale navigation parity complete even when content depth is still partial.
