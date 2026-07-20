# Official ReVX MCP invocation

ReVX is an **MCP Server**. Your editor/agent is the **MCP Host**.

```text
MCP Host (Codex / Cursor / Claude Desktop / …)
  └── stdio JSON-RPC
        └── revx-engine mcp serve --workspace <project>
```

Never put root passwords into MCP configs. Prefer SSH keys (`BatchMode=yes`).

## Production server (deployed)

| Item | Value |
|------|--------|
| Host | `124.222.209.226` |
| OS | OpenCloudOS 9 (x86_64) |
| Engine binary | `/opt/revx/bin/revx-engine` |
| Default workspace | `/var/lib/revx/workspace` (contains `.revx/`) |
| Generated configs on server | `/opt/revx/share/revx/mcp/` |
| Server info name | `revx` |
| Protocol | MCP over stdio JSON-RPC (`2024-11-05`) |

Health check on the server:

```bash
ssh root@124.222.209.226 \
  /opt/revx/bin/revx-engine mcp doctor --workspace /var/lib/revx/workspace
```

## 1) Official remote call (SSH → server MCP)

Use this when the analysis workspace and binary live on the production server.

### Prerequisites

1. SSH public-key login to `root@124.222.209.226` (password auth is fine for bootstrap only).
2. Local private key readable by the Host process (example path: `~/.ssh/revx_mcp_ed25519`).

### Codex / Cursor / Claude Desktop fragment

```json
{
  "mcpServers": {
    "revx": {
      "command": "ssh",
      "args": [
        "-i",
        "/ABS/PATH/TO/revx_mcp_ed25519",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "root@124.222.209.226",
        "/opt/revx/bin/revx-engine",
        "mcp",
        "serve",
        "--workspace",
        "/var/lib/revx/workspace"
      ]
    }
  }
}
```

Replace `/ABS/PATH/TO/revx_mcp_ed25519` with your real private key path.

Equivalent one-liner (for manual smoke):

```bash
ssh -i ~/.ssh/revx_mcp_ed25519 -o BatchMode=yes root@124.222.209.226 \
  /opt/revx/bin/revx-engine mcp serve --workspace /var/lib/revx/workspace
```

### What the Host should call first

Typical agent tool sequence:

1. `project_status` — confirm workspace
2. `analysis_run` — `{ "binary_path": "...", "profile": "fast" }` (upload/path must be visible on the server)
3. `function_search` / `function_profile`
4. `decompile_function` / `xrefs_query` / `string_search`
5. `analysis_brief` / `evidence_pack` for agent-oriented packs

`tools/list` currently exposes the high-level capability surface (project/binary/function/object/analysis tools).

## 2) Official local call (same machine as Host)

When `revx-engine` is installed locally and the project has `.revx/`:

```json
{
  "mcpServers": {
    "revx": {
      "command": "/ABS/PATH/TO/revx-engine",
      "args": [
        "mcp",
        "serve",
        "--workspace",
        "/ABS/PATH/TO/PROJECT"
      ]
    }
  }
}
```

Generate this config:

```bash
revx-engine mcp config --host cursor --workspace /path/to/project --bin /path/to/revx-engine
# or one-click
./deploy/mcp/one-click.sh
```

## 3) Thin CLI bridge

`revx mcp …` forwards to `revx-engine` when `REVX_ENGINE` or a sibling `revx-engine` binary is available:

```bash
revx mcp serve --workspace /path/to/project
revx mcp doctor --workspace /path/to/project
revx mcp config --host generic --workspace /path/to/project
```

## 4) Workspace rules

- `--workspace` is the **project directory** that contains `.revx/`, not the `.revx` folder itself.
- Create if missing:

```bash
revx-engine mcp serve --workspace /var/lib/revx/workspace --init
# or
revx-engine init /var/lib/revx/workspace
```

- Analysis inputs (`analysis_run.binary_path`) must be paths **on the machine where `revx-engine` runs** (for remote MCP, that is the server).

## 5) Security notes

- Do not commit passwords, tokens, or private keys.
- Prefer key-based SSH; disable password login after keys work.
- Rotate any password that was shared in chat or tickets.
- MCP stdio uses process stdout; keep logs on stderr only.

## 6) Operator paths cheat-sheet

```text
/opt/revx/bin/revx-engine
/opt/revx/share/revx/mcp/generic.mcp.json
/opt/revx/share/revx/mcp/cursor.mcp.json
/opt/revx/share/revx/mcp/claude.mcp.json
/opt/revx/share/revx/mcp/codex.mcp.json
/opt/revx/share/revx/mcp/remote-ssh.mcp.json
/var/lib/revx/workspace/.revx/
```

Re-copy a newly built Linux binary:

```bash
scp target/x86_64-unknown-linux-gnu/release/revx-engine root@124.222.209.226:/opt/revx/bin/revx-engine
ssh root@124.222.209.226 'chmod +x /opt/revx/bin/revx-engine && revx-engine mcp doctor --workspace /var/lib/revx/workspace'
```
