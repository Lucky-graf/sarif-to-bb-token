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
// SMART SUMMARY LIMITER (<= 450 chars guaranteed)
// ------------------------------------------------------------

function smartSummary(text) {
  if (!text) return "";

  text = text.trim();

  // First sentence if it fits
  const firstSentence = text.split('. ')[0] + '.';
  if (firstSentence.length <= 450) return firstSentence;

  // If whole text fits
  if (text.length <= 450) return text;

  // Otherwise smart truncate
  let truncated = text.slice(0, 450);
  truncated = truncated.replace(/\s+\S*$/, ''); // cut partial words
  return truncated + "...";
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

  if (!REPO) {
    console.log('Error: specify repo')
    return false
  }

  if (!COMMIT) {
    console.log('Error: specify commit')
    return false
  }

  if (!WORKSPACE) {
    console.log('Error: specify workspace')
    return false
  }

  return true
}

// ------------------------------------------------------------
// SARIF PARSING HELPERS
// ------------------------------------------------------------

const severityMap = {
  'note': 'LOW',
  'warning': 'MEDIUM',
  'error': 'HIGH'
};

const rulesAsMap = (sarifRules) =>
  sarifRules.reduce((map, rule) => ({ ...map, [rule['id']]: rule }), {});

const getPath = (result) =>
  result['locations'][0]['physicalLocation']['artifactLocation']['uri'];

const getLine = (result) => {
  const region = result['locations'][0]['physicalLocation']['region'];
  return region['endLine'] || region['startLine'];
};

const getRuleText = (result, rulesMap) => {
  const rule = rulesMap[result['ruleId']];
  if (!rule) return "";

  if (rule.fullDescription) return rule.fullDescription.text;
  if (rule.shortDescription) return rule.shortDescription.text;

  return "";
};

// ------------------------------------------------------------
// SARIF → Bitbucket annotations
// ------------------------------------------------------------

const mapSarif = (sarif) => {
  const rulesMap = rulesAsMap(sarif.runs[0].tool.driver.rules);

  return sarif.runs[0].results.map(result => {
    const fullText = getRuleText(result, rulesMap);

    return {
      external_id: uuidv4(),
      annotation_type: "VULNERABILITY",
      severity: severityMap[result.level],
      path: getPath(result),
      line: getLine(result),
      summary: smartSummary(fullText),
      details: fullText || result.message.text
    };
  });
};

// ------------------------------------------------------------
// Compute highest severity and counts
// ------------------------------------------------------------

function computeSeverityStats(vulns) {
  const score = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };

  vulns.forEach(v => counts[v.severity]++);

  const highest =
    counts.HIGH > 0 ? "HIGH" :
    counts.MEDIUM > 0 ? "MEDIUM" :
    counts.LOW > 0 ? "LOW" : null;

  return { highest, counts };
}

function severityLabel(sev) {
  if (sev === "HIGH") return "High risk";
  if (sev === "MEDIUM") return "Medium risk";
  if (sev === "LOW") return "Low risk";
  return "No findings";
}

// ------------------------------------------------------------
// MAIN LOGIC
// ------------------------------------------------------------

const sarifToBitBucket = async (sarifRaw) => {
  const sarif = JSON.parse(sarifRaw);
  const scanName = sarif.runs[0].tool.driver.name;
  const scanId = scanName.replace(/\s+/g, "").toLowerCase();

  let vulns = mapSarif(sarif);

  // Stats
  const stats = computeSeverityStats(vulns);

  // Determine result
  const resultStatus =
    stats.highest === "HIGH" ? "FAILED" :
    stats.highest === "MEDIUM" ? "FAILED" :
    "PASSED";

  // Details section
  const details =
    `Security scan completed.\n\n` +
    `Findings by severity:\n` +
    `• HIGH: ${stats.counts.HIGH}\n` +
    `• MEDIUM: ${stats.counts.MEDIUM}\n` +
    `• LOW: ${stats.counts.LOW}\n\n` +
    `Highest severity detected: ${severityLabel(stats.highest)}.\n`;

  // Limit annotations (Bitbucket allows 100)
  if (vulns.length > 100) {
    vulns = vulns.slice(0, 100);
  }

  const config = BB_TOKEN
    ? { headers: { Authorization: `Bearer ${BB_TOKEN}` } }
    : { auth: { username: BB_USER, password: BB_APP_PASSWORD } };

  // ------------------------------------------------------------
  // DELETE OLD REPORT
  // ------------------------------------------------------------
  await axios.delete(
    `${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanId}`,
    config
  );

  // ------------------------------------------------------------
  // CREATE REPORT
  // ------------------------------------------------------------
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

  // ------------------------------------------------------------
  // UPLOAD ANNOTATIONS
  // ------------------------------------------------------------
  await axios.post(
    `${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanId}/annotations`,
    vulns,
    config
  );
};

// ------------------------------------------------------------
// STDIN HANDLING
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
