#!/usr/bin/env node

import axios from 'axios'
import minimist from 'minimist'
import { v4 as uuidv4 } from 'uuid'

const BB_API_URL = 'https://api.bitbucket.org/2.0/repositories'
const argv = minimist(process.argv.slice(2));

const BB_USER = argv['user']
const BB_APP_PASSWORD = argv['password']
const BB_TOKEN = argv['token']
const REPO = argv['repo']
const COMMIT = argv['commit']
const WORKSPACE = argv['workspace']

// ------------------------------------------------------------
// SMART SUMMARY (max 450 chars)
// ------------------------------------------------------------
function smartSummary(text) {
  if (!text) return "";
  text = text.trim();

  const firstSentence = text.split('. ')[0] + '.';
  if (firstSentence.length <= 450) return firstSentence;

  if (text.length <= 450) return text;

  let truncated = text.slice(0, 450);
  truncated = truncated.replace(/\s+\S*$/, '');
  return truncated + "...";
}

// ------------------------------------------------------------
// SEVERITY INFERENCE ENGINE
// ------------------------------------------------------------
function inferSeverity(ruleId, text) {
  const s = (ruleId + " " + text).toLowerCase();

  // CRITICAL
  if (/(rce|remote code|command injection|prototype pollution|sql injection|arbitrary file write|directory traversal)/.test(s))
    return "CRITICAL";

  // HIGH
  if (/(csrf|xss|cross[- ]site|auth bypass|authorization|insecure deserialization|hardcoded|sensitive data|jwt|token)/.test(s))
    return "HIGH";

  // MEDIUM
  if (/(missing integrity|weak crypt|md5|sha1|insecure|http:\/|audit)/.test(s))
    return "MEDIUM";

  return "LOW";
}

// ------------------------------------------------------------
// VALIDATION
// ------------------------------------------------------------
const paramsAreValid = () => {
  if (!BB_TOKEN && !BB_USER) {
    console.log('Error: specify either token or user')
    return false
  }

  if (!BB_TOKEN && !BB_APP_PASSWORD) {
    console.log('Error: specify either token or password')
    return false
  }

  if (!REPO) { console.log('Error: specify repo'); return false }
  if (!COMMIT) { console.log('Error: specify commit'); return false }
  if (!WORKSPACE) { console.log('Error: specify workspace'); return false }

  return true
}

// ------------------------------------------------------------
// SARIF HELPERS
// ------------------------------------------------------------
const rulesAsMap = (rules) =>
  rules.reduce((map, rule) => ({ ...map, [rule.id]: rule }), {});

const getPath = (result) =>
  result.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? "unknown";

const getLine = (result) =>
  result.locations?.[0]?.physicalLocation?.region?.startLine ?? 1;

const getRuleText = (result, rulesMap) => {
  const rule = rulesMap[result.ruleId];
  if (!rule) return "";

  return (
    rule.fullDescription?.text ??
    rule.shortDescription?.text ??
    result.message?.text ??
    ""
  );
};

// ------------------------------------------------------------
// MAP SARIF → Bitbucket ISSUE format
// ------------------------------------------------------------
const mapSarif = (sarif) => {
  const rulesMap = rulesAsMap(sarif.runs[0].tool.driver.rules);

  return sarif.runs[0].results.map(result => {
    const fullText = getRuleText(result, rulesMap);
    const severity = inferSeverity(result.ruleId, fullText);

    return {
      external_id: uuidv4(),
      annotation_type: "ISSUE",
      severity: severity,                  // CRITICAL / HIGH / MEDIUM / LOW
      title: smartSummary(fullText),
      message: fullText,
      path: getPath(result),
      line: getLine(result)
    };
  });
};

// ------------------------------------------------------------
// Compute severity stats
// ------------------------------------------------------------
function computeSeverityStats(vulns) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  vulns.forEach(v => counts[v.severity]++);

  const highest =
    counts.CRITICAL > 0 ? "CRITICAL" :
    counts.HIGH > 0 ? "HIGH" :
    counts.MEDIUM > 0 ? "MEDIUM" :
    "LOW";

  return { highest, counts };
}

function severityLabel(sev) {
  return {
    CRITICAL: "Critical risk",
    HIGH: "High risk",
    MEDIUM: "Medium risk",
    LOW: "Low risk"
  }[sev] || "No findings";
}

// ------------------------------------------------------------
// MAIN FUNCTION
// ------------------------------------------------------------
const sarifToBitBucket = async (sarifRaw) => {
  const sarif = JSON.parse(sarifRaw);
  const scanName = sarif.runs[0].tool.driver.name;
  const scanId = scanName.replace(/\s+/g, "").toLowerCase();

  let vulns = mapSarif(sarif);
  const stats = computeSeverityStats(vulns);

  const resultStatus =
    stats.highest === "CRITICAL" || stats.highest === "HIGH"
      ? "FAILED"
      : "PASSED";

  const details =
    `Security scan summary:\n\n` +
    `Findings by severity:\n` +
    `• CRITICAL: ${stats.counts.CRITICAL}\n` +
    `• HIGH: ${stats.counts.HIGH}\n` +
    `• MEDIUM: ${stats.counts.MEDIUM}\n` +
    `• LOW: ${stats.counts.LOW}\n\n` +
    `Highest severity: ${severityLabel(stats.highest)}.\n`;

  if (vulns.length > 100)
    vulns = vulns.slice(0, 100);

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
      details: details
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
// Handle stdin input
// ------------------------------------------------------------
const getInput = () =>
  new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });

if (paramsAreValid()) {
  getInput().then(sarifToBitBucket).catch(console.error);
}
