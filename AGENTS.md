# AGENTS

## Code

- 写代码不要写注释

## Delivery (Issue + PR + CI)

Target repo: [shiaho777/revx](https://github.com/shiaho777/revx). Integration branch is always `main`.

Humans: see [CONTRIBUTING.md](CONTRIBUTING.md). PR form: [.github/pull_request_template.md](.github/pull_request_template.md).

### Rules

1. Prefer a PR into `main` over direct push for intentional changes.
2. Issue first for intentional code/doc process work. Reuse an open Issue when one tracks the work; otherwise create one.
3. Branch from up-to-date `main`. Prefer `codex/` prefix (e.g. `codex/short-topic`) unless the user or repo convention says otherwise.
4. Open the PR with base `main`. Body must explain what/why, link the Issue, and include `Fixes #N` or `Closes #N` so the Issue closes **on merge only**.
5. Do **not** close the Issue when the PR is opened, while CI is red, or before merge.
6. **CI is the merge gate.** Required check:
   - Workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (`name: ci`)
   - Job id: `test` (GitHub check often shown as `ci / test`)
7. Wait for green; fix and push on red. Do not merge red checks.
8. CI must **not** auto-close Issues. Merge (via `Fixes`/`Closes` in the PR body) closes the Issue.
9. One primary Issue per PR when possible. Extra Issues: link without extra closing keywords unless intentional.
10. No secrets or junk in commits (`target/`, `.revx/`, `*.db`, `*.log`, credentials, IDE caches).
11. Do **not** commit, push, open PRs, or file Issues unless the user asks to deliver, bootstrap, ship, push, or equivalent.
12. If merge permission is missing: still open the PR, comment on the Issue with links, leave the Issue open, hand off to a maintainer when CI is green.

### Flow

```text
Issue open → PR open (Fixes #N, base=main) → CI (ci / test)
  ├─ red  → fix & push (Issue stays open)
  └─ green → merge to main → Issue auto-closes
```

### Exceptions

Only when the user explicitly overrides for that turn (doc-only direct push, hotfix, skip Issue/CI/PR). Record the override in the PR/Issue handoff.
