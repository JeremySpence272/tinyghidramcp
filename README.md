# tinyghidramcp

A minimal Ghidra MCP server for AI agents. Twelve curated tools plus a `pyghidra.exec`
escape hatch — designed from empirical agent-usage data, not from a feature checklist.

## Status

Pre-0.1. Hard fork of [`mrphrazer/ghidra-headless-mcp`](https://github.com/mrphrazer/ghidra-headless-mcp)
in active reduction. See `NOTICE.md` for attribution.

## Design

The tool surface was selected from a corpus of ~290 real agent runs (claude / codex)
against Ghidra MCP servers, analyzed in `../analysis/`. Twelve tools cover ~95% of
observed agent traffic; everything else routes through `pyghidra.exec`.

| Tool                | Purpose                                                            |
|---------------------|--------------------------------------------------------------------|
| `binary.summary`    | One-shot recon: arch, security flags, top symbols, entry           |
| `search.functions`  | Name/regex search over functions                                   |
| `search.strings`    | Defined-strings search with regex + min-length                     |
| `decompile`         | Decompile a single function (address or name)                      |
| `decompile.batch`   | Decompile many functions in one call                               |
| `disassemble`       | Function or byte-range disassembly                                 |
| `xrefs.to`          | Find callers/references to an address                              |
| `xrefs.from`        | Find calls/references from an address                              |
| `callgraph`         | Bounded call-graph traversal in one shot                           |
| `resolve`           | Name → address resolution                                          |
| `pyghidra.exec`     | Escape hatch: arbitrary Python with `currentProgram` bound         |
| `meta.help`         | Per-tool documentation                                             |

## Runtime

- Python 3.11+
- Ghidra 12.1 (`GHIDRA_INSTALL_DIR` must be set)
- stdio transport only

## Operational model

tinyghidramcp expects revbench's container model:

- One server process = one agent run = one Ghidra program loaded.
- The warmed Ghidra project is at the hardcoded path `/var/lib/tinyghidramcp/project/`,
  populated by a separate warm-up step before the server starts. If absent at startup,
  the server exits non-zero.
- Telemetry: every tool call written as JSONL to `$TINYGHIDRAMCP_TELEMETRY_DIR`
  (default `/tmp/tinyghidramcp_telemetry/`; empty string disables).
- Session ID from `$TINYGHIDRAMCP_SESSION_ID` or UUID4 fallback.

## Security model

`pyghidra.exec` runs arbitrary Python as root inside the agent's container, with full
filesystem and Ghidra-API access. The container is the sandbox. Do not expose this
server outside its container.
