import { readFileSync, existsSync } from "node:fs";

export interface IpRecord {
  ip: string;
  totalAttempts: number;
  failedAttempts: number;
  successfulAttempts: number;
  targetedUsernames: string[];
  firstSeen?: string;
  lastSeen?: string;
  sampleEvidence: string[];
  isPotentialBruteForce: boolean;
  riskLevel: "HIGH" | "SUSPICIOUS" | "LOW";
}

export interface AnalysisResult {
  totalLinesAnalyzed: number;
  totalAuthEvents: number;
  totalFailedLogins: number;
  totalSuccessfulLogins: number;
  uniqueIpsObserved: number;
  potentialBruteForceCount: number;
  thresholdUsed: number;
  flaggedIps: IpRecord[];
  allIpSummaries: IpRecord[];
  disclaimer: string;
}

export interface AnalyzeOptions {
  logContent?: string;
  filePath?: string;
  failedThreshold?: number;
}

const DEFAULT_THRESHOLD = 3;

export const SECURITY_DISCLAIMER =
  "IMPORTANT SECURITY NOTICE: Suspicious patterns such as repeated failed login attempts are indicators of potential brute-force activity, but they are NOT definitive proof of an attack or malicious intent. High failure counts frequently occur due to benign factors including misconfigured scripts, cached stale credentials, forgotten passwords by legitimate users, network retry storms, or automated health checks. Always correlate with additional context (user identity, internal asset registers, geo-location, and firewall logs) before executing blocking actions.";

// Regex to extract valid IPv4 addresses
const IPV4_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

// Patterns matching failed login attempts
const FAILED_PATTERNS: RegExp[] = [
  /failed\s+password\s+for\s+(?:invalid\s+user\s+)?([a-zA-Z0-9_.@-]+)/i,
  /authentication\s+fail(?:ure|ed).*?(?:user[=:\s]+['"]?([a-zA-Z0-9_.@-]+)['"]?)/i,
  /authentication\s+fail(?:ure|ed)/i,
  /login\s+fail(?:ed|ure)(?:\s+for\s+user\s+['"]?([a-zA-Z0-9_.@-]+)['"]?)?/i,
  /failed\s+login(?:\s+for\s+['"]?([a-zA-Z0-9_.@-]+)['"]?)?/i,
  /invalid\s+user\s+([a-zA-Z0-9_.@-]+)/i,
  /user\s+['"]?([a-zA-Z0-9_.@-]+)['"]?\s+failed\s+to\s+authenticate/i,
  /POST\s+\S*(?:login|auth|signin)\S*\s+HTTP\/\S+"\s+(?:401|403)/i,
  /status=failed/i,
  /auth_result=failure/i,
];

// Patterns matching successful login attempts
const SUCCESS_PATTERNS: RegExp[] = [
  /accepted\s+(?:password|publickey)\s+for\s+([a-zA-Z0-9_.@-]+)/i,
  /login\s+(?:succeeded|successful)(?:\s+for\s+user\s+['"]?([a-zA-Z0-9_.@-]+)['"]?)?/i,
  /authentication\s+succeeded(?:\s+for\s+user\s+['"]?([a-zA-Z0-9_.@-]+)['"]?)?/i,
  /POST\s+\S*(?:login|auth|signin)\S*\s+HTTP\/\S+"\s+200/i,
  /status=success/i,
  /auth_result=success/i,
];

// Pattern to extract timestamps from common log formats
const TIMESTAMP_REGEX =
  /(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/;

function isValidIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  return parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255);
}

function extractIp(line: string): string | null {
  const match = line.match(IPV4_REGEX);
  if (match && isValidIpv4(match[0])) {
    return match[0];
  }
  return null;
}

function extractTimestamp(line: string): string | undefined {
  const match = line.match(TIMESTAMP_REGEX);
  return match ? match[0] : undefined;
}

function extractUsername(line: string): string | undefined {
  for (const pattern of FAILED_PATTERNS) {
    const match = line.match(pattern);
    if (match && match[1]) {
      return match[1];
    }
  }
  for (const pattern of SUCCESS_PATTERNS) {
    const match = line.match(pattern);
    if (match && match[1]) {
      return match[1];
    }
  }

  // Fallback check for user=xxx or username=xxx
  const fallback = line.match(/(?:user|username|account)=['"]?([a-zA-Z0-9_.@-]+)['"]?/i);
  if (fallback && fallback[1]) {
    return fallback[1];
  }
  return undefined;
}

function isFailedLogin(line: string): boolean {
  return FAILED_PATTERNS.some((pattern) => pattern.test(line));
}

function isSuccessfulLogin(line: string): boolean {
  return SUCCESS_PATTERNS.some((pattern) => pattern.test(line));
}

/**
 * Analyzes log data, detects repeated failed logins, groups attempts by IP,
 * and flags potential brute-force activity.
 */
export function analyzeLogs(options: AnalyzeOptions): AnalysisResult {
  let content = options.logContent ?? "";

  if (options.filePath) {
    if (!existsSync(options.filePath)) {
      throw new Error(`Log file not found at path: ${options.filePath}`);
    }
    content = readFileSync(options.filePath, "utf-8");
  }

  if (!content.trim()) {
    return {
      totalLinesAnalyzed: 0,
      totalAuthEvents: 0,
      totalFailedLogins: 0,
      totalSuccessfulLogins: 0,
      uniqueIpsObserved: 0,
      potentialBruteForceCount: 0,
      thresholdUsed: options.failedThreshold ?? DEFAULT_THRESHOLD,
      flaggedIps: [],
      allIpSummaries: [],
      disclaimer: SECURITY_DISCLAIMER,
    };
  }

  const threshold =
    typeof options.failedThreshold === "number" && options.failedThreshold > 0
      ? options.failedThreshold
      : DEFAULT_THRESHOLD;

  const lines = content.split(/\r?\n/);
  const ipMap = new Map<
    string,
    {
      failedCount: number;
      successCount: number;
      usernames: Set<string>;
      firstSeen?: string;
      lastSeen?: string;
      evidence: string[];
    }
  >();

  let totalAuthEvents = 0;
  let totalFailedLogins = 0;
  let totalSuccessfulLogins = 0;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    const failed = isFailedLogin(line);
    const successful = !failed && isSuccessfulLogin(line);

    if (!failed && !successful) {
      continue;
    }

    totalAuthEvents++;
    if (failed) totalFailedLogins++;
    if (successful) totalSuccessfulLogins++;

    const ip = extractIp(line) ?? "unknown-ip";
    const username = extractUsername(line);
    const timestamp = extractTimestamp(line);

    let entry = ipMap.get(ip);
    if (!entry) {
      entry = {
        failedCount: 0,
        successCount: 0,
        usernames: new Set<string>(),
        firstSeen: timestamp,
        lastSeen: timestamp,
        evidence: [],
      };
      ipMap.set(ip, entry);
    }

    if (failed) {
      entry.failedCount++;
      if (entry.evidence.length < 5) {
        entry.evidence.push(line);
      }
    } else if (successful) {
      entry.successCount++;
    }

    if (username) {
      entry.usernames.add(username);
    }

    if (timestamp) {
      if (!entry.firstSeen) entry.firstSeen = timestamp;
      entry.lastSeen = timestamp;
    }
  }

  const allIpSummaries: IpRecord[] = [];
  const flaggedIps: IpRecord[] = [];

  for (const [ip, data] of ipMap.entries()) {
    const totalAttempts = data.failedCount + data.successCount;
    const isPotentialBruteForce = data.failedCount >= threshold;

    let riskLevel: IpRecord["riskLevel"] = "LOW";
    if (isPotentialBruteForce) {
      riskLevel = data.failedCount >= threshold * 2 ? "HIGH" : "SUSPICIOUS";
    }

    const record: IpRecord = {
      ip,
      totalAttempts,
      failedAttempts: data.failedCount,
      successfulAttempts: data.successCount,
      targetedUsernames: Array.from(data.usernames),
      firstSeen: data.firstSeen,
      lastSeen: data.lastSeen,
      sampleEvidence: data.evidence,
      isPotentialBruteForce,
      riskLevel,
    };

    allIpSummaries.push(record);
    if (isPotentialBruteForce) {
      flaggedIps.push(record);
    }
  }

  // Sort flagged IPs by failed attempts descending
  flaggedIps.sort((a, b) => b.failedAttempts - a.failedAttempts);
  allIpSummaries.sort((a, b) => b.failedAttempts - a.failedAttempts);

  return {
    totalLinesAnalyzed: lines.length,
    totalAuthEvents,
    totalFailedLogins,
    totalSuccessfulLogins,
    uniqueIpsObserved: ipMap.size,
    potentialBruteForceCount: flaggedIps.length,
    thresholdUsed: threshold,
    flaggedIps,
    allIpSummaries,
    disclaimer: SECURITY_DISCLAIMER,
  };
}

/**
 * Formats the analysis result into a clear, readable report for MCP users.
 */
export function formatReport(result: AnalysisResult): string {
  const sections: string[] = [];

  sections.push("# 🔍 AI Log Detective Report");
  sections.push("");
  sections.push("## Summary");
  sections.push(`- **Lines Analyzed:** ${result.totalLinesAnalyzed}`);
  sections.push(`- **Authentication Events:** ${result.totalAuthEvents}`);
  sections.push(`- **Failed Logins:** ${result.totalFailedLogins}`);
  sections.push(`- **Successful Logins:** ${result.totalSuccessfulLogins}`);
  sections.push(`- **Unique IPs Observed:** ${result.uniqueIpsObserved}`);
  sections.push(
    `- **Potential Brute-Force Flags:** ${result.potentialBruteForceCount} IP(s) (threshold: ≥ ${result.thresholdUsed} failures)`
  );
  sections.push("");

  if (result.flaggedIps.length > 0) {
    sections.push("## 🚨 Flagged Potential Brute-Force Activity");
    for (const item of result.flaggedIps) {
      sections.push(`### IP: \`${item.ip}\` [Risk: **${item.riskLevel}**]`);
      sections.push(`- **Failed Attempts:** ${item.failedAttempts}`);
      sections.push(`- **Successful Attempts:** ${item.successfulAttempts}`);
      sections.push(
        `- **Targeted Usernames:** ${
          item.targetedUsernames.length > 0
            ? item.targetedUsernames.map((u) => `\`${u}\``).join(", ")
            : "_None extracted_"
        }`
      );
      if (item.firstSeen || item.lastSeen) {
        sections.push(`- **Window:** ${item.firstSeen ?? "N/A"} → ${item.lastSeen ?? "N/A"}`);
      }
      if (item.sampleEvidence.length > 0) {
        sections.push("- **Sample Evidence:**");
        for (const ev of item.sampleEvidence) {
          sections.push(`  - \`${ev}\``);
        }
      }
      sections.push("");
    }
  } else {
    sections.push("## ✅ No Brute-Force Activity Detected");
    sections.push(`No IP addresses reached the threshold of ${result.thresholdUsed} failed attempts.`);
    sections.push("");
  }

  if (result.allIpSummaries.length > 0) {
    sections.push("## 📋 IP Activity Overview");
    sections.push("| IP Address | Failed | Successful | Risk Level | Targeted Users |");
    sections.push("|---|---|---|---|---|");
    for (const item of result.allIpSummaries) {
      const users =
        item.targetedUsernames.length > 0 ? item.targetedUsernames.join(", ") : "-";
      sections.push(
        `| \`${item.ip}\` | ${item.failedAttempts} | ${item.successfulAttempts} | ${item.riskLevel} | ${users} |`
      );
    }
    sections.push("");
  }

  sections.push("## ⚠️ Analyst Notice");
  sections.push(`> ${result.disclaimer}`);

  return sections.join("\n");
}
