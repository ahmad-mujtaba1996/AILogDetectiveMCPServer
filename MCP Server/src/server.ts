import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { analyzeLogs, formatReport } from "./analyzer.js";

export function createServer(): McpServer {
  const server = new McpServer({
    name: "ai-log-detective",
    version: "1.0.0",
  });

  server.tool(
    "analyze_logs",
    "Analyzes authentication and system logs to detect repeated failed logins, group attempts by IP, and flag potential brute-force activity. Suspicious patterns are highlighted with contextual risk analysis and an explicit disclaimer that suspicious patterns are indicators, not proof of an attack.",
    {
      log_content: z
        .string()
        .optional()
        .describe("Raw text content of the logs to analyze (provide either log_content or file_path)."),
      file_path: z
        .string()
        .optional()
        .describe("Local path to a log file to read and analyze (provide either log_content or file_path)."),
      threshold: z
        .number()
        .int()
        .positive()
        .optional()
        .describe("Minimum number of failed logins from a single IP to flag as potential brute-force (default: 3)."),
    },
    async ({ log_content, file_path, threshold }) => {
      if (!log_content && !file_path) {
        return {
          content: [
            {
              type: "text",
              text: "Error: Please provide either 'log_content' (raw text) or 'file_path' to analyze.",
            },
          ],
          isError: true,
        };
      }

      try {
        const result = analyzeLogs({
          logContent: log_content,
          filePath: file_path,
          failedThreshold: threshold,
        });

        const report = formatReport(result);
        return {
          content: [
            {
              type: "text",
              text: report,
            },
          ],
        };
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        return {
          content: [
            {
              type: "text",
              text: `Error analyzing logs: ${errorMessage}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  return server;
}

export async function runServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Log status exclusively to stderr so MCP JSON-RPC protocol on stdout is not corrupted
  console.error("AI Log Detective MCP Server running on stdio");
}
