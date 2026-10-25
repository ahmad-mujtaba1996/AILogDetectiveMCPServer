#!/usr/bin/env node
import { runServer } from "./server.js";

runServer().catch((error) => {
  console.error("Fatal error starting AI Log Detective MCP server:", error);
  process.exit(1);
});
