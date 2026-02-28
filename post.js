const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs-extra");
const { execSync } = require("child_process");
const axios = require("axios");
const { runBaselineAnalysis } = require("./baseline");

const FIM_LOG_PATH = "/tmp/roc-fim-events.jsonl";

// ----------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------
async function readLog(logType, logPath) {
  try {
    if (await fs.pathExists(logPath)) {
      const content = await fs.readFile(logPath, "utf8");
      if (content.trim()) {
        core.info(`--- ROC ${logType} ---`);
        core.info(content);
        core.info(`--- End ROC ${logType} ---`);
      }
      return content;
    }
  } catch (e) {
    core.warning(`Error reading ROC ${logType}: ${e.message}`);
  }
  return "";
}

async function readSummaryStats() {
  try {
    if (await fs.pathExists("/tmp/roc-summary.json")) {
      return await fs.readJson("/tmp/roc-summary.json");
    }
  } catch (e) {
    core.debug(`Could not read roc-summary.json: ${e.message}`);
  }
  return null;
}

async function getContainerStats(containerId) {
  if (!containerId) return null;
  try {
    const out = execSync(
      `sudo docker inspect --format='{{json .State}}' ${containerId} 2>/dev/null`,
      { encoding: "utf8" }
    ).trim();
    return JSON.parse(out);
  } catch (_) {
    return null;
  }
}

// ----------------------------------------------------------------
// FIM event reader + uploader
// ----------------------------------------------------------------
async function readFIMEvents() {
  try {
    if (!(await fs.pathExists(FIM_LOG_PATH))) return [];
    const content = await fs.readFile(FIM_LOG_PATH, "utf8");
    const events = [];
    for (const line of content.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try { events.push(JSON.parse(t)); } catch { /* skip malformed */ }
    }
    return events;
  } catch (e) {
    core.warning(`[FIM] Error reading fim-events log: ${e.message}`);
    return [];
  }
}

async function uploadFIMEvents(events, apiKey, serverUrl) {
  if (!apiKey || events.length === 0) return;
  const base = (serverUrl || "https://api.codexsecurity.io").replace(/\/graphql\/?$/, '');
  try {
    await axios.post(`${base}/api/v1/roc/fim/events`, {
      repo: process.env.GITHUB_REPOSITORY || "",
      runId: process.env.GITHUB_RUN_ID || "",
      job: process.env.GITHUB_JOB || "",
      branch: process.env.GITHUB_REF_NAME || "",
      events,
    }, {
      headers: { Authorization: `apiKey ${apiKey}`, "Content-Type": "application/json" },
      timeout: 15000,
    });
    core.info(`[FIM] ✅ Uploaded ${events.length} FIM event(s) to backend`);
  } catch (e) {
    core.warning(`[FIM] Could not upload events to backend: ${e.message}`);
  }
}

// ----------------------------------------------------------------
// GitHub Step Summary writer
// ----------------------------------------------------------------
async function writeStepSummary(stats, egressPolicy, containerId, baselineReport, fimEvents) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) {
    core.debug("GITHUB_STEP_SUMMARY not set, skipping summary write.");
    return;
  }

  const repo = process.env.GITHUB_REPOSITORY || "unknown";
  const runId = process.env.GITHUB_RUN_ID || "";
  const job = process.env.GITHUB_JOB || "";
  const workflow = process.env.GITHUB_WORKFLOW || "";

  let secretSection = "";
  let alertIcon = "✅";

  if (stats && stats.secrets_found > 0) {
    alertIcon = "🚨";
    secretSection = `
### 🚨 Secrets Detected in Network Traffic

| Pattern | Destination | Step |
|---------|-------------|------|
${(stats.secret_details || []).map(s =>
      `| \`${s.pattern || "regex"}\` | \`${s.destination || "unknown"}\` | ${s.step || "-"} |`
    ).join("\n")}

> **Action Required:** Rotate the above credentials immediately.
`;
  }

  let egressSection = "";
  if (stats && stats.blocked_connections > 0) {
    egressSection = `
### 🚫 Blocked Egress Connections (${stats.blocked_connections})

| Destination | Port | Step |
|-------------|------|------|
${(stats.blocked_details || []).map(b =>
      `| \`${b.host || b.ip}\` | ${b.port} | ${b.step || "-"} |`
    ).join("\n")}
`;
  }

  // Automated baseline section
  let baselineSection = "";
  if (baselineReport) {
    if (baselineReport.firstRun) {
      baselineSection = `
### 📊 Egress Baseline

> **First run** — establishing baseline with ${Object.keys(baselineReport.knownDestinations).length} destinations observed.  
> Future runs will flag any **new** outbound connections not seen today.
`;
    } else {
      const newRows = baselineReport.newDestinations.length > 0
        ? baselineReport.newDestinations.map(d => `| \`${d}\` | ⚠️ NEW |`).join("\n")
        : "| *(none)* | ✅ |";
      if (baselineReport.newDestinations.length > 0) {
        alertIcon = alertIcon === "✅" ? "⚠️" : alertIcon;
      }
      baselineSection = `
### 📊 Egress Baseline (run #${baselineReport.runs})

| Destination | Status |
|-------------|--------|
${newRows}

**Known destinations:** ${baselineReport.knownDestinations.length} &nbsp; **Baseline size:** ${baselineReport.totalKnown}
`;
    }
  }

  // FIM violations section
  let fimSection = "";
  if (fimEvents && fimEvents.length > 0) {
    alertIcon = alertIcon === "✅" ? "🔍" : alertIcon;
    const rows = fimEvents.slice(0, 20).map(e =>
      `| \`${e.path || "-"}\` | ${e.action || "?"} | ${e.step_name || "-"} | \`${(e.sha256 || "").slice(0, 12)}…\` |`
    ).join("\n");
    const more = fimEvents.length > 20 ? `\n> _…and ${fimEvents.length - 20} more events_` : "";
    fimSection = `
### 🔍 File Integrity Violations (${fimEvents.length})

| File | Action | Step | SHA256 (after) |
|------|--------|------|----------------|
${rows}${more}
`;
  }

  const tlsCount = stats ? (stats.tls_connections || 0) : "–";
  const secretsFound = stats ? (stats.secrets_found || 0) : "–";
  const uniqueDests = stats ? (stats.unique_destinations || 0) : "–";
  const blockedCount = stats ? (stats.blocked_connections || 0) : "–";

  const serverUrl = core.getState("serverUrl") || "https://api.codexsecurity.io";
  const dashboardUrl = `${serverUrl}/projects`;

  const md = `
## ${alertIcon} O3 Security ROC Agent — Security Summary

**Workflow:** \`${workflow}\` | **Job:** \`${job}\` | **Run:** [#${runId}](https://github.com/${repo}/actions/runs/${runId})

| Metric | Value |
|--------|-------|
| TLS/SSL connections captured | **${tlsCount}** |
| Secrets detected in traffic | **${secretsFound}** |
| Unique egress destinations | **${uniqueDests}** |
| Connections blocked | **${blockedCount}** |
| FIM file violations | **${fimEvents ? fimEvents.length : "-"}** |
| Egress policy | \`${egressPolicy || "audit"}\` |

${secretSection}
${egressSection}
${fimSection}
${baselineSection}
---
🛡️ Powered by [O3 Security ROC Agent](https://github.com/o3security/roc-agent)  
[View full analysis →](${dashboardUrl})
`;

  try {
    await fs.appendFile(summaryPath, md);
    core.info("✅ Security summary written to GitHub Step Summary.");
  } catch (e) {
    core.warning(`Could not write Step Summary: ${e.message}`);
  }
}


// ----------------------------------------------------------------
// Main cleanup
// ----------------------------------------------------------------
async function cleanup() {
  const egressPolicy = core.getState("egressPolicy") || "audit";
  const containerId = core.getState("containerId") || "";
  const apiKey = core.getInput("api_key") || "";
  const serverUrl = core.getState("serverUrl") || "https://api.codexsecurity.io";

  core.info("O3 Security ROC Agent: stopping monitor and collecting results...");

  try {
    // 1. Signal ROC binary to flush summary
    const rocPid = core.getState("rocPid");
    if (rocPid) {
      core.info(`Sending SIGINT to ROC process PID: ${rocPid}`);
      try { await exec.exec("sudo", ["kill", "-SIGINT", rocPid]); } catch (_) { }
      await sleep(3000);
    }
    // 2. Stop container
    if (containerId) {
      core.info(`Stopping ROC container: ${containerId}`);
      try { await exec.exec("sudo", ["docker", "stop", "--time=5", containerId]); } catch (_) { }
    }
  } catch (e) {
    core.warning(`Error during ROC stop: ${e.message}`);
  }

  // 3. Read logs
  await readLog("stdout", "/tmp/roc-stdout.log");
  await readLog("stderr", "/tmp/roc-stderr.log");

  // 4. Read FIM events + upload to backend
  const fimEvents = await readFIMEvents();
  if (fimEvents.length > 0) {
    core.warning(`[FIM] ⚠️  ${fimEvents.length} file integrity violation(s) detected during build!`);
    await uploadFIMEvents(fimEvents, apiKey, serverUrl);
  }

  // 5. Run automated baseline analysis (load → diff → save)
  let baselineReport = null;
  if (core.getInput("baseline_enabled") !== "false") {
    try {
      baselineReport = await runBaselineAnalysis(apiKey, serverUrl);
      if (baselineReport.newDestinations.length > 0) {
        core.warning(
          `[Baseline] ⚠️  ${baselineReport.newDestinations.length} new egress destination(s): ` +
          baselineReport.newDestinations.join(", ")
        );
      } else if (!baselineReport.firstRun) {
        core.info("[Baseline] ✅ All egress matches baseline — no new connections");
      }
    } catch (e) {
      core.warning(`[Baseline] Analysis failed (non-fatal): ${e.message}`);
    }
  }

  // 6. Read stats + write GitHub Step Summary
  const stats = await readSummaryStats();
  await writeStepSummary(stats, egressPolicy, containerId, baselineReport, fimEvents);

  // 7. Warn on secrets
  if (stats && stats.secrets_found > 0) {
    core.warning(
      `🚨 O3 Security: ${stats.secrets_found} secret(s) detected in network traffic. ` +
      "Review the Step Summary above and rotate affected credentials."
    );
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

cleanup();
