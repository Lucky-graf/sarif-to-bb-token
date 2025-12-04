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

// ------------------------------
// SMART SUMMARY IMPLEMENTATION
// ------------------------------

function smartSummary(text) {
  if (!text) return "";

  // Normalize — trim spaces
  text = text.trim();

  // 1. Try using the first sentence
  const firstSentence = text.split('. ')[0] + '.';
  if (firstSentence.length <= 450) {
    return firstSentence;
  }

  // 2. If original fits — return it
  if (text.length <= 450) {
    return text;
  }

  // 3. Otherwise truncate smartly
  let truncated = text.slice(0, 450);

  // Cut off partial words
  truncated = truncated.replace(/\s+\S*$/, '');

  return truncated + '...';
}

// ------------------------------
// VALIDATION
// ------------------------------

const paramsAreValid = () => {
  if (!BB_TOKEN && !BB_USER) {
    console.log('Error: specify either token or user')
    return false
  }

  if (!BB_TOKEN && !BB_APP_PASSWORD) {
    console.log('Error: specify either token or password')
    return false
  }

  if (REPO == null) {
    console.log('Error: specify repo')
    return false
  }

  if (COMMIT == null) {
    console.log('Error: specify commit')
    return false
  }

  if (WORKSPACE == null) {
    console.log('Error: specify workspace')
    return false
  }

  return true
}


const rulesAsMap = (sarifRules) => {
  return sarifRules.reduce((map, rule) => ({ ...map, [rule['id']]: rule }), {})
}

const getPath = (sarifResult) => {
  return sarifResult['locations'][0]['physicalLocation']['artifactLocation']['uri']
}

const getLine = (sarifResult) => {
  const region = sarifResult['locations'][0]['physicalLocation']['region']
  if (region['endLine'] != null) {
    return region['endLine']
  }
  return region['startLine']
}

const getSummary = (sarifResult, rulesMap) => {
  const ruleId = sarifResult['ruleId']
  const rule = rulesMap[ruleId]

  if (rule && rule['fullDescription'] != null) {
    return rule['fullDescription']['text']
  }

  if (rule && rule['shortDescription'] != null) {
    return rule['shortDescription']['text']
  }

  return ""
}


const mapSarif = (sarif) => {
  const severityMap = {
    'note': 'LOW',
    'warning': 'MEDIUM',
    'error': 'HIGH'
  }

  const rulesMap = rulesAsMap(sarif['runs'][0]['tool']['driver']['rules'])

  return sarif['runs'][0]['results']
    .map(result => {
      const fullSummary = getSummary(result, rulesMap);

      return {
        external_id: uuidv4(),
        annotation_type: "VULNERABILITY",
        severity: severityMap[result['level']],
        path: getPath(result),
        line: getLine(result),

        // SMART SUMMARY IMPLEMENTED HERE
        summary: smartSummary(fullSummary),

        // Full details moved here, Bitbucket allows >450 chars
        details: fullSummary || result['message']['text']
      }
    })
}

const getScanType = (sarif) => {
  const scanName = sarif['runs'][0]['tool']['driver']['name']
  return {
    id: scanName.replace(/\s+/g, "").toLowerCase(),
    title: scanName,
    name: scanName,
    mapper: mapSarif,
    count: sarif['runs'][0]['results'].length
  }
}

const sarifToBitBucket = async (sarifRawOutput) => {
  const sarifResult = JSON.parse(sarifRawOutput);
  const scanType = getScanType(sarifResult);

  let vulns = scanType.mapper(sarifResult);

  let details = `This repository contains ${scanType['count']} ${scanType['name']} vulnerabilities`;

  if (vulns.length > 100) {
    vulns = vulns.slice(0, 100)
    details = `${details} (first 100 vulnerabilities shown)`
  }

  const config = BB_TOKEN
    ? { headers: { 'Authorization': `Bearer ${BB_TOKEN}` } }
    : { auth: { username: BB_USER, password: BB_APP_PASSWORD } }

  // Delete previous report
  await axios.delete(
    `${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanType['id']}`,
    config
  )

  // Create base report
  await axios.put(
    `${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanType['id']}`,
    {
      title: scanType['title'],
      details: details,
      report_type: "SECURITY",
      reporter: "sarif-to-bitbucket",
      result: "PASSED"
    },
    config
  )

  // Upload annotations (vulnerabilities)
  await axios.post(
    `${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanType['id']}/annotations`,
    vulns,
    config
  )
}

const getInput = () => {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    let data = '';

    stdin.setEncoding('utf8');
    stdin.on('data', (chunk) => { data += chunk });
    stdin.on('end', () => resolve(data));
    stdin.on('error', reject);
  });
}

if (paramsAreValid()) {
  getInput()
    .then(sarifToBitBucket)
    .catch(console.error)
}
