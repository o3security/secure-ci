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
  // 1. Try the binary-written summary first
  try {
    if (await fs.pathExists("/tmp/roc-summary.json")) {
      return await fs.readJson("/tmp/roc-summary.json");
    }
  } catch (e) {
    core.debug(`Could not read roc-summary.json: ${e.message}`);
  }

  // 2. Synthesize stats from egress JSONL (DPI binary doesn't write summary.json yet)
  try {
    const EGRESS_LOG = "/tmp/roc-egress-log.jsonl";
    if (!(await fs.pathExists(EGRESS_LOG))) return null;
    const content = await fs.readFile(EGRESS_LOG, "utf8");
    const lines = content.split("\n").filter(l => l.trim());
    if (lines.length === 0) return null;

    const events = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    const uniqueDests = new Set(events.map(e => { const d = e.domain || e.ip || ''; const p = e.port || 443; return `${d}:${p}`; }));
    const secretEvents = events.filter(e => e.secrets === true);

    // Try to load step context (written by action.yml pre-step)
    let stepContext = {};
    try {
      if (await fs.pathExists('/tmp/roc-step-context.json')) {
        stepContext = await fs.readJson('/tmp/roc-step-context.json');
      }
    } catch (e) { /* non-fatal */ }

    return {
      tls_connections: events.filter(e => e.source !== 'tcpmonitor').length,
      unique_destinations: uniqueDests.size,
      secrets_found: secretEvents.length,
      secret_details: secretEvents.map(e => ({
        pattern: 'detected',
        destination: e.domain || e.ip,
        step: stepContext.step_name || e.comm || '',
        comm: e.comm || '',
        cmdline: e.cmdline || '',
        parent_comm: e.parent_comm || '',
      })),
      blocked_connections: 0,
      // Rich per-event data for the captures table
      egress_events: events.map(e => ({
        domain: e.domain || e.ip || '',
        ip: e.ip || '',
        port: e.port || 443,
        comm: e.comm || '',
        cmdline: e.cmdline || '',
        parent_comm: e.parent_comm || '',
        source: e.source || 'openssl',
        secrets: !!e.secrets,
        timestamp: e.timestamp || '',
      })),
      synthesized: true,
    };
  } catch (e) {
    core.debug(`Could not synthesize stats: ${e.message}`);
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
// Parse step_name from DPI evidence string
// Evidence looks like: "2026-03-01T06:13:22Z ##[group]Run echo \"Testing...\""
// Returns the step name extracted from the ##[group]Run prefix, or null
// ----------------------------------------------------------------
function parseStepName(evidence) {
  if (!evidence) return null;
  // Match ##[group]Run <step text>
  const m = evidence.match(/##\[group\]Run (.+?)(?:\n|$)/);
  if (m) return m[1].trim().slice(0, 80);
  return null;
}

// ----------------------------------------------------------------
// Upload full pipeline security finding to backend
// Called at job-end with all accumulated data.
// ----------------------------------------------------------------
async function uploadPipelineVuln(apiKey, serverUrl, fimEvents, baselineReport, stats) {
  if (!apiKey) {
    core.info('[PipelineVuln] No API key — skipping');
    return;
  }
  core.info(`[PipelineVuln] Starting upload (serverUrl=${serverUrl})`);

  let stepContext = {};
  try {
    if (await fs.pathExists('/tmp/roc-step-context.json')) {
      stepContext = await fs.readJson('/tmp/roc-step-context.json');
    }
  } catch (_) { /* non-fatal */ }

  // Build secrets array from egress log entries that had secrets=true
  const secrets = [];
  try {
    const EGRESS_LOG = "/tmp/roc-egress-log.jsonl";
    if (await fs.pathExists(EGRESS_LOG)) {
      const content = await fs.readFile(EGRESS_LOG, "utf8");
      for (const line of content.split("\n")) {
        const t = line.trim();
        if (!t) continue;
        try {
          const ev = JSON.parse(t);
          if (ev.secrets && ev.secrets !== true) {
            // ev.secrets is an array of {pattern_id, matched_text, evidence, evidence_type}
            for (const s of (Array.isArray(ev.secrets) ? ev.secrets : [])) {
              secrets.push({
                pattern_id: s.pattern_id || 'unknown',
                severity: s.severity || 'high',
                // Store full matched_text — UI handles masking
                matched_text: s.matched_text || null,
                destination: ev.domain || ev.ip || null,
                step_name: parseStepName(s.evidence) || ev.comm || null,
                evidence_snippet: (s.evidence || '').slice(0, 300),
                // Full process tree
                process: {
                  comm: ev.comm || null,
                  cmdline: ev.cmdline || null,
                  parent_comm: ev.parent_comm || null,
                  parent_cmdline: ev.parent_cmdline || null,
                },
              });
            }
          } else if (ev.secrets === true) {
            // Older format — just flag, no detail
            secrets.push({
              pattern_id: 'detected',
              severity: 'high',
              matched_text: null,
              destination: ev.domain || ev.ip || null,
              step_name: ev.comm || null,
              process: { comm: ev.comm, cmdline: ev.cmdline, parent_comm: ev.parent_comm, parent_cmdline: ev.parent_cmdline },
            });
          }
        } catch (_) { /* skip malformed lines */ }
      }
    }
  } catch (e) {
    core.debug(`[PipelineVuln] Could not read egress log: ${e.message}`);
  }

  // Egress deviations from baseline report
  // baselineReport.deviations is a NUMBER (count), not an array.
  // baselineReport.newDestinations OR high_severity_deviations is the actual array.
  const rawDeviations = Array.isArray(baselineReport?.high_severity_deviations)
    ? baselineReport.high_severity_deviations
    : Array.isArray(baselineReport?.newDestinations)
      ? baselineReport.newDestinations
      : [];
  // Parse egress deviation strings: "104.16.8.34:443:npm install lod" → structured objects
  function parseDeviationEntry(d) {
    if (typeof d === 'object' && d !== null) {
      // Already structured — parse host:port from destination if needed
      const dest = d.key || d.destination || '';
      const colonIdx = dest.indexOf(':');
      const host = colonIdx > -1 ? dest.slice(0, colonIdx) : dest;
      const rest = colonIdx > -1 ? dest.slice(colonIdx + 1) : '';
      const portEnd = rest.indexOf(':');
      const port = portEnd > -1 ? rest.slice(0, portEnd) : rest;
      return {
        host: host || null,
        port: port || null,
        destination: dest,
        severity: d.severity || 'medium',
        is_new: true,
        process_comm: d.comm || null,
        process_cmdline: d.cmdline || null,
        parent_comm: d.parent_comm || null,
      };
    }
    // String format: "IP:PORT:SOME CMDLINE" e.g. "104.16.8.34:443:npm install lodash"
    const str = String(d);
    const parts = str.split(':');
    const host = parts[0] || null;
    const port = parts[1] || null;
    // Everything after IP:PORT is part of the process/command
    const processPart = parts.slice(2).join(':').trim() || null;
    return {
      host,
      port,
      destination: host && port ? `${host}:${port}` : str,
      severity: 'medium',
      is_new: true,
      process_comm: processPart ? processPart.split(' ')[0] : null,
      process_cmdline: processPart || null,
      parent_comm: null,
    };
  }
  const egress_deviations = rawDeviations.map(parseDeviationEntry);

  // FIM events
  const fim = fimEvents.map(e => ({
    path: e.path || e.filename || null,
    event_type: e.event_type || e.type || 'write',
    severity: e.severity || 'medium',
    timestamp: e.timestamp || null,
    process: { comm: e.comm, cmdline: e.cmdline, parent_comm: e.parent_comm },
  }));

  core.info(`[PipelineVuln] Collected: secrets=${secrets.length} egress_deviations=${egress_deviations.length} fim=${fim.length}`);

  // Skip if nothing to report
  if (secrets.length === 0 && egress_deviations.length === 0 && fim.length === 0) {
    core.info('[PipelineVuln] Nothing to report — skipping vulnerability creation');
    return;
  }

  const body = {
    repo: stepContext.repository || process.env.GITHUB_REPOSITORY || '',
    run_id: stepContext.run_id || process.env.GITHUB_RUN_ID || '',
    run_number: stepContext.run_number || process.env.GITHUB_RUN_NUMBER || '',
    workflow: stepContext.workflow || process.env.GITHUB_WORKFLOW || '',
    job: stepContext.job || process.env.GITHUB_JOB || '',
    sha: stepContext.sha || process.env.GITHUB_SHA || '',
    actor: stepContext.actor || process.env.GITHUB_ACTOR || '',
    ref: process.env.GITHUB_REF || '',
    branch: stepContext.branch || process.env.GITHUB_REF_NAME || '',
    session_id: stats?.session_id || null,
    project_name: stepContext.repository || process.env.GITHUB_REPOSITORY || '',
    secrets,
    fim_events: fim,
    egress_deviations,
  };

  try {
    const gqlEndpoint = serverUrl.endsWith('/graphql')
      ? serverUrl
      : `${serverUrl.replace(/\/$/, '')}/graphql`;

    const mutation = `
      mutation UploadPipelineSecurityFindings(
        $project_name: String
        $session_id: String
        $source: String!
        $pipeline_context: JSON!
      ) {
        UploadPipelineSecurityFindings(
          project_name: $project_name
          session_id: $session_id
          source: $source
          pipeline_context: $pipeline_context
        ) { status message }
      }
    `;

    const resp = await axios.post(
      gqlEndpoint,
      {
        query: mutation,
        variables: {
          project_name: body.project_name || body.repo || '',
          session_id: body.session_id || null,
          source: 'github_actions',
          pipeline_context: body,
        },
      },
      {
        headers: {
          authorization: `apiKey ${apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 20000,
      }
    );

    const result = resp.data?.data?.UploadPipelineSecurityFindings;
    // Capture any GQL-level errors (these are NOT HTTP errors, so catch won't catch them)
    if (resp.data?.errors?.length) {
      core.warning(`[PipelineVuln] GQL errors: ${JSON.stringify(resp.data.errors)}`);
    } else if (result?.status === false) {
      core.warning(`[PipelineVuln] Mutation returned false: ${result.message}`);
    } else {
      core.info(`[PipelineVuln] ✅ Vulnerability recorded: ${result?.message || 'ok'}`);
    }
  } catch (e) {
    // Non-fatal — pipeline still succeeds
    const detail = e.response?.data ? JSON.stringify(e.response.data).slice(0, 300) : e.message;
    core.warning(`[PipelineVuln] Could not record pipeline vuln (non-fatal): ${detail}`);
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

| Pattern | Destination | Step | Process | Parent | Command |
|---------|-------------|------|---------|--------|---------|
${(stats.secret_details || []).map(s => {
      const step = s.step || '-';
      const proc = s.comm ? `\`${s.comm}\`` : '-';
      const parent = s.parent_comm ? `\`${s.parent_comm}\`` : '-';
      const cmd = s.cmdline ? `\`${s.cmdline.slice(0, 60)}\`` : '-';
      return `| \`${s.pattern || 'regex'}\` | \`${s.destination || 'unknown'}\` | ${step} | ${proc} | ${parent} | ${cmd} |`;
    }).join("\n")}

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
    // Normalise field names — backend path and cache-only path use different keys
    const newDests = baselineReport.newDestinations ?? [];
    const knownDests = baselineReport.knownDestinations ?? baselineReport.egressClassified?.map(e => e.key) ?? [];
    const runCount = baselineReport.runs ?? baselineReport.run_count ?? 1;
    const isFirstRun = baselineReport.firstRun ?? (runCount === 1 && newDests.length === 0);

    if (isFirstRun) {
      baselineSection = `
### 📊 Egress Baseline

> **First run** — establishing baseline with ${knownDests.length} destinations observed.  
> Future runs will flag any **new** outbound connections not seen today.
`;
    } else {
      const newRows = newDests.length > 0
        ? newDests.map(d => `| \`${d}\` | ⚠️ NEW |`).join("\n")
        : "| *(none)* | ✅ |";
      if (newDests.length > 0) {
        alertIcon = alertIcon === "✅" ? "⚠️" : alertIcon;
      }
      baselineSection = `
### 📊 Egress Baseline (run #${runCount})

| Destination | Status |
|-------------|--------|
${newRows}

**Known destinations:** ${knownDests.length}
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

  // Captured connections section — shows supply chain process context
  let capturesSection = "";
  const captureEvents = stats?.egress_events || [];
  if (captureEvents.length > 0) {
    const rows = captureEvents.slice(0, 30).map(e => {
      const dest = `${e.domain || e.ip}:${e.port}`;
      const proc = e.comm ? `\`${e.comm}\`` : "–";
      const cmd = e.cmdline ? `\`${e.cmdline.slice(0, 60)}\`` : "–";
      const par = e.parent_comm ? `\`${e.parent_comm}\`` : "–";
      const src = e.source === "tcpmonitor" ? "TCP" : "TLS/SSL";
      const sec = e.secrets ? "🚨" : "";
      return `| \`${dest}\` | ${proc} | ${cmd} | ${par} | ${src} ${sec}|`;
    }).join("\n");
    const more = captureEvents.length > 30 ? `\n> _…and ${captureEvents.length - 30} more connections_` : "";
    capturesSection = `
### 🔗 Captured Connections (${captureEvents.length})

| Destination | Process | Command | Parent | Source |
|-------------|---------|---------|--------|--------|
${rows}${more}

> _Supply chain context: **Process** shows which binary made the request, **Parent** shows what spawned it (e.g. \`npm\`→\`bash\`→\`curl\`→evil.io)_
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
${capturesSection}
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

  // 3. Full diagnostics — always print so failures are visible
  core.info("════════════════════════════════════════");
  core.info("ROC AGENT DIAGNOSTICS");
  core.info("════════════════════════════════════════");
  core.info(`containerId state: "${containerId || '(none)'}"`);
  core.info(`rocPid state: "${core.getState("rocPid") || '(none)'}"`);
  core.info(`serverUrl: "${serverUrl}"`);
  core.info(`egressPolicy: "${egressPolicy}"`);

  // Docker container status
  try {
    const psOut = execSync("sudo docker ps -a --format 'table {{.ID}}\\t{{.Image}}\\t{{.Status}}\\t{{.Names}}' 2>&1", { encoding: "utf8" });
    core.info("── docker ps -a ──");
    core.info(psOut || "(empty)");
  } catch (e) { core.info(`docker ps error: ${e.message}`); }

  // Docker logs from our container
  if (containerId) {
    try {
      const dockerLogs = execSync(`sudo docker logs --tail 100 ${containerId} 2>&1`, { encoding: "utf8" });
      core.info(`── docker logs (${containerId}) ──`);
      core.info(dockerLogs || "(empty)");
    } catch (e) { core.info(`docker logs error: ${e.message}`); }
  }

  // All ROC /tmp files
  const tmpFiles = [
    "/tmp/roc-stdout.log",
    "/tmp/roc-stderr.log",
    "/tmp/roc-egress-log.jsonl",
    "/tmp/roc-fim-events.jsonl",
    "/tmp/roc-summary.json",
    "/tmp/roc-inline-policy.yaml",
    "/tmp/roc-inline-patterns.yaml",
    "/tmp/roc-step-context.json",
  ];
  for (const f of tmpFiles) {
    try {
      if (await fs.pathExists(f)) {
        const content = await fs.readFile(f, "utf8");
        const lines = content.trim().split("\n").length;
        core.info(`── ${f} (${content.length} bytes, ${lines} lines) ──`);
        core.info(content.trim() || "(empty)");
      } else {
        core.info(`── ${f}: NOT FOUND`);
      }
    } catch (e) { core.info(`── ${f}: read error: ${e.message}`); }
  }
  core.info("════════════════════════════════════════");


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

  // 7. Upload pipeline security vulnerability (secrets + FIM + deviations) to backend
  await uploadPipelineVuln(apiKey, serverUrl, fimEvents, baselineReport, stats);

  // 8. Warn on secrets
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
