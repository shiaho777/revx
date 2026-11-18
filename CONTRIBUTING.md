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

Coding agents should follow the same loop in [AGENTS.md](AGENTS.md) (Delivery section). DEX/APK agent routing lives in [skill/revx/SKILL.md](skill/revx/SKILL.md); `revx mcp install` copies it next to host MCP configs.

### Exemptions

- Fully automated bot/catalog PRs may omit an Issue when maintainers already treat them as process-exempt; still prefer linking context when possible.

## Local checks

Run the **same gate CI runs** before pushing (workflow `ci`, job `test`). A subset passing locally does not mean CI will pass:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo test -p revx-loader -p revx-workspace -p revx-daemon --features revx-loader/containers
```

Notes:
- Clippy treats warnings as errors (`-D warnings`); dead code and lint nits fail the gate.
- The full-workspace test run includes the cross-process `output_stability` suites (DEX and native). If you touch phi allocation, renaming, or rendering order, run them repeatedly — a single green run can hide `HashMap`-iteration nondeterminism.
- `corpus_smoke` / `corpus_golden` only run in CI when `REVX_CORPUS_DIR` is set; they are optional locally and require an external corpus that is not in the repo.
- System `libsqlite3` / `pkg-config` is required for non-bundled SQLite builds (same as CI).

### macOS toolchain caveat

If a broken/absent Swift toolchain hijacks the default `cc`/`ar`, pin the system toolchain and avoid full-LTO release rebuilds (they can exhaust memory):

```bash
CC=/usr/bin/clang AR=/usr/bin/ar RUSTFLAGS="-C linker=/usr/bin/clang" \
  CARGO_PROFILE_RELEASE_LTO=false cargo build -p revx-engine --release --features revx-engine/full-loader -j 2
```

Use the same `CC`/`AR`/`RUSTFLAGS` prefix for test/clippy builds when the default linker fails.

## Branch protection (recommended)

On `main`, require status check **ci / test** (job id `test` in workflow `ci`) before merge. Branch protection is repo-admin configuration and is not applied by docs alone.
