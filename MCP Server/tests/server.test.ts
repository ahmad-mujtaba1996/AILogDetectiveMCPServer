import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/server.js";

describe("AI Log Detective - MCP Server Integration", () => {
  async function setupClientAndServer() {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer();
    await server.connect(serverTransport);

    const client = new Client(
      { name: "test-client", version: "1.0.0" },
      { capabilities: {} }
    );
    await client.connect(clientTransport);

    return {
      client,
      server,
      cleanup: async () => {
        await client.close();
        await server.close();
      },
    };
  }

  it("registers analyze_logs tool with proper schema", async () => {
    const { client, cleanup } = await setupClientAndServer();
    try {
      const toolList = await client.listTools();
      const tool = toolList.tools.find((t) => t.name === "analyze_logs");
      assert.ok(tool, "Expected analyze_logs tool to be registered");
      assert.ok(tool.description?.includes("brute-force"));
      assert.ok(tool.inputSchema);
    } finally {
      await cleanup();
    }
  });

  it("executes analyze_logs tool with inline log content", async () => {
    const { client, cleanup } = await setupClientAndServer();
    try {
      const logs = [
        "2026-10-26T09:00:01Z auth-srv: Failed password for admin from 192.168.1.100",
        "2026-10-26T09:00:03Z auth-srv: Failed password for admin from 192.168.1.100",
        "2026-10-26T09:00:05Z auth-srv: Failed password for admin from 192.168.1.100",
        "2026-10-26T09:00:10Z auth-srv: Accepted password for user1 from 192.168.1.50",
      ].join("\n");

      const response = await client.callTool({
        name: "analyze_logs",
        arguments: {
          log_content: logs,
          threshold: 3,
        },
      });

      assert.ok(!response.isError);
      assert.ok(Array.isArray(response.content));
      assert.equal(response.content[0].type, "text");
      const text = (response.content[0] as { type: "text"; text: string }).text;

      assert.ok(text.includes("192.168.1.100"));
      assert.ok(text.includes("Flagged Potential Brute-Force Activity"));
      assert.ok(text.includes("⚠️ Analyst Notice"));
      assert.ok(text.includes("NOT definitive proof of an attack"));
    } finally {
      await cleanup();
    }
  });

  it("executes analyze_logs tool with file_path argument", async () => {
    const { client, cleanup } = await setupClientAndServer();
    try {
      const response = await client.callTool({
        name: "analyze_logs",
        arguments: {
          file_path: resolve(process.cwd(), "sample.log"),
          threshold: 3,
        },
      });

      assert.ok(!response.isError);
      const text = (response.content[0] as { type: "text"; text: string }).text;
      assert.ok(text.includes("203.0.113.42"));
      assert.ok(text.includes("198.51.100.89"));
      assert.ok(text.includes("Analyst Notice"));
    } finally {
      await cleanup();
    }
  });

  it("returns error message when neither log_content nor file_path is provided", async () => {
    const { client, cleanup } = await setupClientAndServer();
    try {
      const response = await client.callTool({
        name: "analyze_logs",
        arguments: {},
      });

      assert.equal(response.isError, true);
      const text = (response.content[0] as { type: "text"; text: string }).text;
      assert.ok(text.includes("Please provide either 'log_content'"));
    } finally {
      await cleanup();
    }
  });
});
