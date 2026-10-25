import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { analyzeLogs, formatReport, SECURITY_DISCLAIMER } from "../src/analyzer.js";

describe("AI Log Detective - Log Analyzer", () => {
  it("detects repeated failed logins, groups by IP, and flags potential brute-force activity", () => {
    const sampleLog = `
2026-10-26T08:14:02Z server sshd: Accepted publickey for deploy from 10.0.0.15 port 52341
2026-10-26T08:15:10Z server sshd: Failed password for invalid user admin from 203.0.113.42 port 41201
2026-10-26T08:15:14Z server sshd: Failed password for invalid user root from 203.0.113.42 port 41204
2026-10-26T08:15:18Z server sshd: Failed password for invalid user test from 203.0.113.42 port 41208
2026-10-26T08:16:22Z server sshd: Failed password for bob from 192.168.1.55 port 52360
2026-10-26T08:16:30Z server sshd: Accepted password for bob from 192.168.1.55 port 52362
    `.trim();

    const result = analyzeLogs({
      logContent: sampleLog,
      failedThreshold: 3,
    });

    assert.equal(result.totalFailedLogins, 4);
    assert.equal(result.totalSuccessfulLogins, 2);
    assert.equal(result.uniqueIpsObserved, 3);
    assert.equal(result.potentialBruteForceCount, 1);

    // Verify flagged IP details
    const flagged = result.flaggedIps[0];
    assert.ok(flagged);
    assert.equal(flagged.ip, "203.0.113.42");
    assert.equal(flagged.failedAttempts, 3);
    assert.equal(flagged.isPotentialBruteForce, true);
    assert.deepEqual(flagged.targetedUsernames.sort(), ["admin", "root", "test"].sort());

    // Verify non-flagged IP (normal behavior)
    const bobIp = result.allIpSummaries.find((x) => x.ip === "192.168.1.55");
    assert.ok(bobIp);
    assert.equal(bobIp.failedAttempts, 1);
    assert.equal(bobIp.successfulAttempts, 1);
    assert.equal(bobIp.isPotentialBruteForce, false);

    // Verify disclaimer is present
    assert.ok(result.disclaimer.includes("NOT definitive proof of an attack"));
  });

  it("analyzes logs from a file path and produces formatted report with disclaimer", () => {
    const sampleFilePath = resolve(process.cwd(), "sample.log");
    const result = analyzeLogs({
      filePath: sampleFilePath,
      failedThreshold: 3,
    });

    assert.ok(result.totalLinesAnalyzed > 0);
    assert.ok(result.flaggedIps.length >= 2, "Expected at least 2 flagged IPs in sample.log");

    const report = formatReport(result);
    assert.ok(report.includes("# 🔍 AI Log Detective Report"));
    assert.ok(report.includes("203.0.113.42"));
    assert.ok(report.includes("198.51.100.89"));
    assert.ok(report.includes("⚠️ Analyst Notice"));
    assert.ok(
      report.includes("indicators of potential brute-force activity, but they are NOT definitive proof")
    );
  });

  it("handles empty input gracefully", () => {
    const result = analyzeLogs({ logContent: "" });
    assert.equal(result.totalLinesAnalyzed, 0);
    assert.equal(result.flaggedIps.length, 0);
    assert.equal(result.disclaimer, SECURITY_DISCLAIMER);
  });
});
