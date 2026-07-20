# ReVX MCP Server deploy

ReVX is an **MCP Server**. The **MCP Host** (Codex, Cursor, Claude Desktop, …) launches it.

```text
Host (Codex / Cursor / …)
  └── spawn command/args (stdio JSON-RPC)
        └── revx-engine mcp serve --workspace <project>
```

`revx` / `revx-engine` CLI is the **deploy entrypoint and human CLI**, not the Host.

## One-click

From the repository root (or any dir with this tree):

```bash
./deploy/mcp/one-click.sh
```

Environment:

| Variable | Default | Meaning |
|----------|---------|---------|
| `REVX_PREFIX` | `~/.local` | install prefix (`bin/`, `share/revx/mcp/`) |
| `REVX_WORKSPACE` | cwd if `.revx` exists, else repo root | analysis workspace project dir |
| `REVX_INIT_WORKSPACE` | `1` for one-click | create `.revx` if missing |
| `REVX_ENGINE` | auto | override engine binary path |

What it does:

1. `cargo build -p revx -p revx-engine --release`
2. `revx-engine mcp install --write-config …` → `~/.local/bin/revx-engine` + host config samples
3. `mcp doctor` health check
4. prints a ready-to-paste MCP config

## Manual start (stdio)

Hosts should spawn this (do not wrap in extra shells for production configs):

```bash
revx-engine mcp serve --workspace /path/to/project
```

Helper for local smoke:

```bash
./deploy/mcp/start-mcp.sh
```

## Other helpers

```bash
./deploy/mcp/doctor.sh
./deploy/mcp/print-config.sh generic
./deploy/mcp/print-config.sh cursor
./deploy/mcp/print-config.sh claude
./deploy/mcp/print-config.sh codex
```

## Engine commands

```bash
revx-engine mcp serve [--workspace PATH] [--init]
revx-engine mcp doctor [--workspace PATH]
revx-engine mcp config --host generic|cursor|claude|codex [--workspace PATH] [--bin PATH]
revx-engine mcp install [--prefix PATH] [--workspace PATH] [--write-config] [--init-workspace]
```

Thin CLI forwards: `revx mcp …` → `revx-engine mcp …`.

## Host wiring

1. Run `./deploy/mcp/one-click.sh`
2. Open `~/.local/share/revx/mcp/*.json` (or stdout from `print-config.sh`)
3. Merge the `mcpServers.revx` block into your Host config
4. Restart the Host
5. Confirm tools such as `project_status`, `function_search`, `decompile_function`

### Cursor

Merge into Cursor MCP settings (often `mcp.json`). Template: `templates/cursor.mcp.json`.

### Claude Desktop

Merge into Claude Desktop config `mcpServers`. Template: `templates/claude_desktop.mcp.json`.

### Codex

Merge into Codex MCP server settings. Template: `templates/codex.mcp.json`.

## Notes

- stdout is the MCP protocol stream; logs must stay on stderr
- workspace path is the project directory that contains `.revx/`
- optional long-lived analysis daemon (`revx daemon start`) is separate from MCP stdio lifecycle


## Official production invocation

See **[OFFICIAL.md](OFFICIAL.md)** for the supported Host configs:

- remote SSH MCP to the production server (`124.222.209.226`)
- local stdio MCP
- workspace path rules and security notes
