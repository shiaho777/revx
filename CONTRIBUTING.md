# Contributing

## Delivery loop

This project uses **Issue → PR → main → CI → merge**.

1. **Open or reuse a GitHub Issue** for the work (problem, scope, acceptance).
2. **Branch from `main`** (prefer `codex/<topic>`).
3. **Open a PR into `main`** using [.github/pull_request_template.md](.github/pull_request_template.md).
   - Include `Fixes #N` or `Closes #N` so the Issue closes **when the PR merges**, not when it opens.
4. **Wait for CI.** Required check: workflow `ci`, job `test` (often shown as **ci / test**). See [.github/workflows/ci.yml](.github/workflows/ci.yml).
5. **Merge only when CI is green.** The linked Issue then auto-closes via the PR keyword.
6. Do **not** close the Issue early while the PR is open or CI is red. CI does not close Issues.

Coding agents should follow the same loop in [AGENTS.md](AGENTS.md) (Delivery section).

### Exemptions

- Fully automated bot/catalog PRs may omit an Issue when maintainers already treat them as process-exempt; still prefer linking context when possible.

## Local checks

```bash
cargo check -p revx-core -p revx-analysis -p revx-loader -p revx-daemon -p revx-engine
cargo test -p revx-analysis --test parity_suite --test corpus_smoke --test corpus_golden
```

System `libsqlite3` / `pkg-config` is required for non-bundled SQLite builds (same as CI).

## Branch protection (recommended)

On `main`, require status check **ci / test** (job id `test` in workflow `ci`) before merge. Branch protection is repo-admin configuration and is not applied by docs alone.
