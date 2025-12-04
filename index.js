#!/usr/bin/env node

import axios from "axios";
import minimist from "minimist";
import { v4 as uuidv4 } from "uuid";
import path from "path";

const BB_API_URL = "https://api.bitbucket.org/2.0/repositories";
const argv = minimist(process.argv.slice(2));

// CLI options
const BB_USER = argv["user"];
const BB_APP_PASSWORD = argv["password"];
const BB_TOKEN = argv["token"];
const REPO = argv["repo"];
const COMMIT = argv["commit"];
const WORKSPACE = argv["workspace"];

const FAIL_ON_HIGH = argv["fail-on-high"] || false;
const FAIL_ON_CRITICAL = argv["fail-on-critical"] || false;
const MAX_ANNOTATIONS = argv["max-annotations"] ?? 100;

// ------------------------------------------------------------
// RELATIVE PATH NORMALIZATION
// ------------------------------------------------------------
function normalizePath(p) {
  if (!p) return "unknown";

  // Convert Windows-style slashes
  p = p.replace(/\\/g, "/");

  // Remove URI prefixes like file://
  p = p.replace(/^file:\/\//, "");

  // Trim leading slashes
  p = p.replace(/^\/+/, "");

  const cwd = process.cwd().replace(/\\/g, "/");

  // Remove only EXACT match of working dir prefix
  if (p.startsWith(cwd)) {
    p = p.slice(cwd.length);
    p = p.replace(/^\/+/, "");
  }

  // DO NOT remove "app/" or "src/" etc.
  // Keep the first directory level always.

  return p.trim();
}

// ------------------------------------------------------------
// SMART SUMMARY (≤450 chars)
// ------------------------------------------------------------
function smartSummary(text) {
  if (!text) return "";

  text = text.trim();

  const LIMIT = 450;

  // If the text fits, return as-is
  if (text.length <= LIMIT) {
    return text;
  }

  // Cut to LIMIT first
  let cut = text.slice(0, LIMIT);

  // Avoid cutting mid-word → rollback to last space
  if (cut.includes(" ")) {
    cut = cut.slice(0, cut.lastIndexOf(" "));
  }

  return cut + "...";
}


// ------------------------------------------------------------
// ENHANCED SEVERITY INFERENCE ENGINE (v2.1.0)
// ------------------------------------------------------------
function inferSeverity(ruleId, text) {
  const s = (ruleId + " " + text).toLowerCase();

  // CRITICAL
  if (/(rce|remote code|command injection|prototype pollution|sql injection|path traversal|arbitrary file write|takeover)/.test(s))
    return "CRITICAL";

  // HIGH
  if (/(csrf|xss|cross[- ]site|auth bypass|authorization|hardcoded|jwt|token|insecure deserialization|open redirect)/.test(s))
    return "HIGH";

  // MEDIUM
  if (/(missing integrity|weak crypt|md5|sha1|audit|insecure configuration|skip-tls|insecure)/.test(s))
    return "MEDIUM";

  // LOW
  return "LOW";
}

// ------------------------------------------------------------
// BASIC VALIDATION
// ------------------------------------------------------------
const paramsAreValid = () => {
  if (!BB_TOKEN && !BB_USER) {
    console.log("Error: specify either token or user");
    return false;
  }

  if (!BB_TOKEN && !BB_APP_PASSWORD) {
    console.log("Error: specify either token or password");
    return false;
  }

  if (!REPO || !COMMIT || !WORKSPACE) {
    console.log("Error: repo/commit/workspace required");
    return false;
  }

  return true;
};

// ------------------------------------------------------------
// SARIF HELPERS
// ------------------------------------------------------------
const rulesAsMap = (rules) =>
  rules.reduce((map, rule) => ({ ...map, [rule.id]: rule }), {});

const getRuleText = (result, rulesMap) => {
  const rule = rulesMap[result.ruleId];
  return (
    rule?.fullDescription?.text ??
    rule?.shortDescription?.text ??
    result.message?.text ??
    ""
  );
};

// ------------------------------------------------------------
// MAP SARIF → Bitbucket ISSUE Annotations
// ------------------------------------------------------------
function mapSarif(sarif) {
  const rulesMap = rulesAsMap(sarif.runs[0].tool.driver.rules);

  let items = sarif.runs[0].results.map((result) => {
    const fullText = getRuleText(result, rulesMap);
    const severity = inferSeverity(result.ruleId, fullText);

    const relPath = normalizePath(
      result.locations?.[0]?.physicalLocation?.artifactLocation?.uri
    );

    return {
      external_id: uuidv4(),
      annotation_type: "ISSUE",
      severity: severity,
      title: smartSummary(fullText),
      summary: smartSummary(fullText), // REQUIRED FIELD
      message: fullText,
      path: relPath,
      line:
        result.locations?.[0]?.physicalLocation?.region?.startLine ?? 1,
      ruleId: result.ruleId,
    };
  });

  // Deduplicate issues
  const unique = new Map();
  items.forEach((i) =>
    unique.set(`${i.ruleId}_${i.path}_${i.line}`, i)
  );

  // Sorted by severity priority
  return [...unique.values()].sort(
    (a, b) =>
      ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(a.severity) -
      ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(b.severity)
  );
}

// ------------------------------------------------------------
// Severity stats + Markdown details
// ------------------------------------------------------------
function buildDetails(vulns) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  vulns.forEach(v => counts[v.severity]++);

  const highest =
    counts.CRITICAL > 0 ? "CRITICAL" :
    counts.HIGH > 0 ? "HIGH" :
    counts.MEDIUM > 0 ? "MEDIUM" : "LOW";

  // Bitbucket-safe formatting (no \n rendering)
  let details = "";
  details += "Security Scan Summary  ";
  details += "Findings by severity:  ";
  details += `• CRITICAL: ${counts.CRITICAL}  `;
  details += `• HIGH: ${counts.HIGH}  `;
  details += `• MEDIUM: ${counts.MEDIUM}  `;
  details += `• LOW: ${counts.LOW}  `;
  details += `Highest severity: ${highest}`;

  return { summary: details, highest };
}


// ------------------------------------------------------------
// MAIN FUNCTION
// ------------------------------------------------------------
const sarifToBitBucket = async (sarifRaw) => {
  const sarif = JSON.parse(sarifRaw);
  const scanName = sarif.runs[0].tool.driver.name;
  const scanId = scanName.replace(/\s+/g, "").toLowerCase();

  let vulns = mapSarif(sarif);
  const { summary, highest } = buildDetails(vulns);

  // Determine PR fail/pass state
  let resultStatus = "PASSED";
  if (highest === "CRITICAL") resultStatus = "FAILED";
  if (FAIL_ON_HIGH && (highest === "HIGH" || highest === "CRITICAL"))
    resultStatus = "FAILED";
  if (FAIL_ON_CRITICAL && highest === "CRITICAL")
    resultStatus = "FAILED";

  // Limit annotations
  if (vulns.length > MAX_ANNOTATIONS)
    vulns = vulns.slice(0, MAX_ANNOTATIONS);

  const config = BB_TOKEN
    ? { headers: { Authorization: `Bearer ${BB_TOKEN}` } }
    : { auth: { username: BB_USER, password: BB_APP_PASSWORD } };

  // DELETE OLD REPORT
  await axios.delete(
    `${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanId}`,
    config
  );

  // CREATE NEW REPORT
  await axios.put(
    `${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanId}`,
    {
      title: `${scanName} Security Scan`,
      report_type: "SECURITY",
      reporter: "sarif-to-bb-token",
      result: resultStatus,
      details: summary,
    },
    config
  );

  // UPLOAD ANNOTATIONS
  await axios.post(
    `${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanId}/annotations`,
    vulns,
    config
  );
};

// ------------------------------------------------------------
// READ STDIN
// ------------------------------------------------------------
const getInput = () =>
  new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });

if (paramsAreValid()) {
  getInput().then(sarifToBitBucket).catch(console.error);
}
