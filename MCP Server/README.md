# 🕵️ AI Log Detective MCP Server

A minimal Model Context Protocol (MCP) server built with **TypeScript**, the official **`@modelcontextprotocol/sdk`**, and **Zod**. It uses **stdio** transport for direct integration with **Claude Code** in terminal environments (such as Antigravity).

It provides a single tool, `analyze_logs`, to inspect authentication and system logs, detect repeated failed logins, group attempts by IP, and flag potential brute-force activity.

---

## 🚀 Features

- **Standard MCP Protocol**: Communicates via standard input/output (`stdio`) without databases, background daemons, or web frameworks.
- **`analyze_logs` Tool**:
  - Detects failed and accepted login events across standard authentication logs (SSH `sshd`, PAM, common web/API auth logs).
  - Groups attempts by IP address, tracking total attempts, failure count, success count, and targeted user accounts.
  - Flags potential brute-force attacks when failures exceed a configurable threshold (default: 3).
  - Explicitly documents that suspicious patterns are indicators of risk, not definitive proof of an attack.
- **Zero bloat**: No frontend, no database, no Docker containers, no external backend framework.

---

## 📦 Project Structure

```text
.
├── src/
│   ├── analyzer.ts       # Log parsing, IP grouping, and reporting logic
│   ├── server.ts         # MCP Server instance and tool definition using Zod
│   └── index.ts          # CLI entry point running stdio transport
├── tests/
│   ├── analyzer.test.ts  # Automated unit tests for log analysis logic
│   └── server.test.ts    # Automated integration tests for MCP protocol & tool
├── sample.log            # Sample authentication log file for testing & demos
├── tsconfig.json         # TypeScript compiler configuration (ESM / NodeNext)
├── package.json          # Package manifest & scripts
└── README.md             # Documentation
```

---

## 🛠️ Setup & Installation

### Prerequisites
- Node.js v18+ (tested on Node v22.17.0)
- npm v10+ (tested on npm 11.4.2)
- Claude Code CLI (`claude`)

### 1. Install Dependencies
```bash
npm install
```

### 2. Build the Server
```bash
npm run build
```
This compiles the TypeScript source code into `dist/index.js`.

### 3. Run Automated Tests
```bash
npm test
```
Runs both unit tests (analysis engine) and integration tests (MCP protocol over in-memory transport).

---

## 🔌 Connecting to Claude Code in Antigravity

Claude Code supports configuring MCP servers via CLI or a project-scoped `.mcp.json` file.

### Option A: Using the Claude Code CLI (Recommended)

Run the following command inside this project folder:

```bash
claude mcp add ai-log-detective -- node "$(pwd)/dist/index.js"
```

Or with an explicit project scope:

```bash
claude mcp add --scope project ai-log-detective -- node "/Users/syedahmadmujtaba/Downloads/Assignments_App/MCP Server/dist/index.js"
```

### Option B: Project Configuration File (`.mcp.json`)

Create or update `.mcp.json` in the root of this project:

```json
{
  "mcpServers": {
    "ai-log-detective": {
      "command": "node",
      "args": [
        "/Users/syedahmadmujtaba/Downloads/Assignments_App/MCP Server/dist/index.js"
      ]
    }
  }
}
```

---

## ✅ Verifying the Server in Claude Code

### 1. Check Server Connection Status
Run in your terminal:
```bash
claude mcp list
```
Expected output:
```text
ai-log-detective: node /path/to/dist/index.js - ✔ Connected
```

### 2. Inspect Server Details
```bash
claude mcp get ai-log-detective
```

### 3. Test the Tool in a Claude Code Session
Start a Claude Code session:
```bash
claude
```
In the prompt, ask Claude:
> *"Use the analyze_logs tool to check sample.log and summarize any suspicious IPs."*

Claude will invoke `analyze_logs` and return the structured report.

---

## 🔍 Tool Specification: `analyze_logs`

### Inputs (Schema validated via Zod)

| Parameter | Type | Required | Description |
|---|---|---|---|
| `log_content` | `string` | Optional* | Raw text of logs to analyze directly. |
| `file_path` | `string` | Optional* | Path to a local log file on disk. |
| `threshold` | `number` | Optional | Minimum failed attempts to flag as brute-force (default: `3`). |

*\* At least one of `log_content` or `file_path` must be provided.*

### Sample Report Output

```markdown
# 🔍 AI Log Detective Report

## Summary
- **Lines Analyzed:** 15
- **Authentication Events:** 12
- **Failed Logins:** 10
- **Successful Logins:** 2
- **Unique IPs Observed:** 4
- **Potential Brute-Force Flags:** 2 IP(s) (threshold: ≥ 3 failures)

## 🚨 Flagged Potential Brute-Force Activity
### IP: `203.0.113.42` [Risk: **HIGH**]
- **Failed Attempts:** 6
- **Successful Attempts:** 0
- **Targeted Usernames:** `admin`, `root`, `administrator`, `guest`, `test`, `support`
- **Window:** 2026-10-26T08:20:01Z → 2026-10-26T08:20:21Z
- **Sample Evidence:**
  - `2026-10-26T08:20:01Z server-01 sshd[1055]: Failed password for invalid user admin from 203.0.113.42 port 41201 ssh2`

### IP: `198.51.100.89` [Risk: **HIGH**]
- **Failed Attempts:** 4
- **Successful Attempts:** 0
- **Targeted Usernames:** `root`
- **Window:** 2026-10-26T08:25:00Z → 2026-10-26T08:25:09Z

## 📋 IP Activity Overview
| IP Address | Failed | Successful | Risk Level | Targeted Users |
|---|---|---|---|---|
| `203.0.113.42` | 6 | 0 | HIGH | admin, root, administrator, guest, test, support |
| `198.51.100.89` | 4 | 0 | HIGH | root |
| `192.168.1.55` | 1 | 1 | LOW | bob |
| `10.0.0.15` | 0 | 1 | LOW | deploy |

## ⚠️ Analyst Notice
> IMPORTANT SECURITY NOTICE: Suspicious patterns such as repeated failed login attempts are indicators of potential brute-force activity, but they are NOT definitive proof of an attack or malicious intent. High failure counts frequently occur due to benign factors including misconfigured scripts, cached stale credentials, forgotten passwords by legitimate users, network retry storms, or automated health checks. Always correlate with additional context before executing blocking actions.
```

---

## 🛠️ Troubleshooting

### 1. `Cannot find module dist/index.js`
- **Cause**: The TypeScript project has not been compiled yet.
- **Fix**: Run `npm run build` from the project root.

### 2. Claude Code reports `Connection failed` or `Pending approval`
- **Cause**: Project-scoped (`.mcp.json`) servers require one-time approval upon Claude startup.
- **Fix**: Launch `claude` in the workspace directory and press `Enter` / confirm when prompted to approve the `ai-log-detective` server.
- To check status: run `claude mcp get ai-log-detective`.

### 3. Changes to TypeScript code not showing up in Claude
- **Cause**: Claude runs `dist/index.js`.
- **Fix**: Rebuild with `npm run build` after modifying any code in `src/`, then restart your Claude Code session (`/exit` and run `claude`).

### 4. `node: command not found` in Claude Code
- **Cause**: The `node` executable is not in Claude's default subshell PATH.
- **Fix**: Use the absolute Node path when adding the server:
  ```bash
  claude mcp add ai-log-detective -- /usr/local/bin/node "/Users/syedahmadmujtaba/Downloads/Assignments_App/MCP Server/dist/index.js"
  ```
