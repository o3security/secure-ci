const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs-extra");
const { execSync } = require("child_process");
const axios = require("axios");
// Note: baseline analysis is now done via IngestCIBaseline GraphQL mutation (no REST import needed)

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

async function readSummaryStats(apiKey, serverUrl) {
  // 1. Try the binary-written summary first
  try {
    if (await fs.pathExists("/tmp/roc-summary.json")) {
      return await fs.readJson("/tmp/roc-summary.json");
    }
  } catch (e) {
    core.debug(`Could not read roc-summary.json: ${e.message}`);
  }

  // 2. Synthesize stats from egress JSONL (written by egress-interceptor on host)
  //    NOTE: The DPI binary runs inside Docker and writes directly to the API,
  //    not to the host filesystem. So this JSONL will be empty when binary is the
  //    sole capture source. We fall through to the API query in that case.
  try {
    const EGRESS_LOG = "/tmp/roc-egress-log.jsonl";
    if (await fs.pathExists(EGRESS_LOG)) {
      const content = await fs.readFile(EGRESS_LOG, "utf8");
      const lines = content.split("\n").filter(l => l.trim());
      if (lines.length > 0) {
        const events = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
        const uniqueDests = new Set(events.map(e => { const d = e.domain || e.ip || ''; const p = e.port || 443; return `${d}:${p}`; }));
        const secretEvents = events.filter(e => e.secrets === true || (Array.isArray(e.secrets) && e.secrets.length > 0));
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
          })),
          blocked_connections: 0,
          synthesized: true,
        };
      }
    }
  } catch (e) {
    core.debug(`Could not synthesize stats from egress log: ${e.message}`);
  }

  // 3. API fallback: query backend for the vuln the binary created for this run.
  //    The binary runs inside Docker so it writes secrets directly to the API
  //    (UploadTrafficRuntimeData), not to any host filesystem file.
  //    We query for the PIPELINE_SECURITY vuln for this project+run to get real counts.
  if (apiKey && serverUrl) {
    try {
      const runId = process.env.GITHUB_RUN_ID || '';
      const repo = process.env.GITHUB_REPOSITORY || '';
      const gqlEndpoint = serverUrl.endsWith('/graphql') ? serverUrl : `${serverUrl.replace(/\/$/, '')}/graphql`;
      const query = `
        query GetPipelineVuln($project_name: String, $run_id: String) {
          GetPipelineVulnByRun(project_name: $project_name, run_id: $run_id) {
            pipeline_context
          }
        }
      `;
      const resp = await axios.post(gqlEndpoint, {
        query,
        variables: { project_name: repo, run_id: runId },
      }, {
        headers: { authorization: `apiKey ${apiKey}`, 'Content-Type': 'application/json' },
        timeout: 8000,
      });
      const pCtx = resp.data?.data?.GetPipelineVulnByRun?.pipeline_context;
      if (pCtx) {
        const captures = pCtx.captures || [];
        const secrets = pCtx.secrets || captures.flatMap(c => c.secrets || []);
        const dests = new Set(captures.map(c => c.request?.host || c.dst_ip).filter(Boolean));
        core.info(`[SummaryStat] Got vuln stats from API: secrets=${secrets.length} captures=${captures.length}`);
        return {
          tls_connections: captures.length,
          unique_destinations: dests.size,
          secrets_found: secrets.length,
          secret_details: secrets.map(s => ({
            pattern: s.pattern_id || 'detected',
            destination: s.destination || null,
          })),
          blocked_connections: 0,
          from_api: true,
        };
      }
    } catch (e) {
      core.debug(`[SummaryStat] API query fallback failed (non-fatal): ${e.message}`);
    }
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


// ----------------------------------------------------------------
// Upload egress baseline deviations and FIM events to backend.
// Secrets → Go binary via UploadTrafficRuntimeData (during job).
// FIM     → Go binary via UploadFIMFindings (at SIGTERM shutdown).
// post.js → only egress deviation baseline comparison remains here.
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

  // ── Build egress deviations ───────────────────────────────────────────────

  // Source 1: egress JSONL log (from egress-interceptor or roc binary) — has full request data
  const egressLogEntries = [];
  try {
    const EGRESS_LOG = "/tmp/roc-egress-log.jsonl";
    if (await fs.pathExists(EGRESS_LOG)) {
      const content = await fs.readFile(EGRESS_LOG, "utf8");
      for (const line of content.split("\n")) {
        const t = line.trim();
        if (!t) continue;
        try {
          const ev = JSON.parse(t);
          // Skip entries that are just "secrets=true" flags (not real egress)
          if (ev.secrets === true) continue;
          const host = ev.domain || ev.ip || null;
          const port = ev.port ? String(ev.port) : null;
          if (!host) continue;
          egressLogEntries.push({
            host,
            port,
            destination: host && port ? `${host}:${port}` : host,
            severity: ev.severity || 'info',
            is_new: false, // these are all observed connections
            protocol: ev.protocol || null,
            process_comm: ev.comm || null,
            process_cmdline: ev.cmdline || null,
            parent_comm: ev.parent_comm || null,
            // Full request captured by egress-interceptor
            request: ev.request
              ? {
                method: ev.request.method || null,
                uri: ev.request.uri || null,
                host: ev.request.host || host,
                url: ev.request.url || null,
                headers: ev.request.headers || null,
              }
              : null,
            timestamp: ev.timestamp || null,
          });
        } catch (_) { /* skip malformed */ }
      }
    }
  } catch (e) {
    core.debug(`[PipelineVuln] Could not read egress log for full requests: ${e.message}`);
  }

  // Source 2: baseline deviations — high-severity / new destinations
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
        request: d.request || null,
      };
    }
    // String format: "IP:PORT:SOME CMDLINE" e.g. "104.16.8.34:443:npm install lodash"
    const str = String(d);
    const parts = str.split(':');
    const host = parts[0] || null;
    const port = parts[1] || null;
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
      request: null,
    };
  }
  const baselineDeviations = rawDeviations.map(parseDeviationEntry);

  // Merge: mark baseline deviations with is_new=true, enrich with request data from log if available
  const deviationDestSet = new Set(baselineDeviations.map(d => d.destination));
  for (const entry of egressLogEntries) {
    if (deviationDestSet.has(entry.destination)) {
      // Enrich the baseline deviation with full request data from log
      const bd = baselineDeviations.find(d => d.destination === entry.destination);
      if (bd && entry.request) bd.request = entry.request;
      if (bd && entry.process_comm && !bd.process_comm) bd.process_comm = entry.process_comm;
      if (bd && entry.process_cmdline && !bd.process_cmdline) bd.process_cmdline = entry.process_cmdline;
    }
  }
  // Final list: baseline deviations (enriched) + any log entries NOT in baseline (all observed traffic)
  const egress_deviations = [
    ...baselineDeviations,
    ...egressLogEntries.filter(e => !deviationDestSet.has(e.destination)),
  ];


  // FIM events
  const fim = fimEvents.map(e => ({
    path: e.path || e.filename || null,
    event_type: e.event_type || e.type || 'write',
    severity: e.severity || 'medium',
    timestamp: e.timestamp || null,
    process: { comm: e.comm, cmdline: e.cmdline, parent_comm: e.parent_comm },
  }));

  core.info(`[PipelineVuln] Collected: egress_deviations=${egress_deviations.length} fim=${fim.length} stats.secrets=${stats?.secrets_found ?? 0}`);

  // Skip if nothing to report — avoids creating empty findings
  const statsSecrets = stats?.secrets_found ?? 0;
  if (egress_deviations.length === 0 && fim.length === 0 && statsSecrets === 0) {
    core.info('[PipelineVuln] Nothing to report (no deviations, FIM events, or secrets) — skipping mutation');
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
    secrets: [],    // populated by Go binary via UploadTrafficRuntimeData — not from post.js
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
  let baselineSection = '';
  if (baselineReport) {
    const newDestsArr = baselineReport.newDestinations ?? [];
    const newDestsSet = new Set(newDestsArr);
    const egressEntries = baselineReport.egressEntries ?? [];
    const knownDests = baselineReport.knownDestinations ?? egressEntries.map(e => e.key);
    const runCount = baselineReport.runCount ?? baselineReport.run_count ?? baselineReport.runs ?? 1;
    const isFirstRun = baselineReport.firstRun ?? (runCount === 1);
    const obsCount = baselineReport.observations ?? knownDests.length;
    const phase = baselineReport.phase || 'learning';

    if (newDestsArr.length > 0) alertIcon = alertIcon === '✅' ? '⚠️' : alertIcon;

    // Process tree: parent_comm → comm
    const procTree = (e) => {
      if (e.parent_comm && e.comm && e.parent_comm !== e.comm) return `\`${e.parent_comm}\` → \`${e.comm}\``;
      if (e.comm) return `\`${e.comm}\``;
      return '–';
    };

    // Build a row for every entry, sorted NEW-first
    const sorted = [...egressEntries].sort((a, b) => {
      const aNew = newDestsSet.has(a.key) ? 0 : 1;
      const bNew = newDestsSet.has(b.key) ? 0 : 1;
      return aNew - bNew;
    });

    const destRows = sorted.length > 0
      ? sorted.map(e => {
        const badge = newDestsSet.has(e.key) ? '⚠️ **NEW**' : (e.status === 'trusted' ? '✅ trusted' : '🔵 baseline');
        const count = e.occurrence_count > 1 ? ` ×${e.occurrence_count}` : '';
        return `| \`${e.key}\`${count} | ${procTree(e)} | ${badge} |`;
      }).join('\n')
      : '| *(no destinations recorded yet — binary flush pending)* | – | – |';

    const phaseNote = phase === 'active' ? 'Active — deviations flagged' : `Learning (${runCount}/5 runs)`;
    const firstRunNote = isFirstRun
      ? `**First run** — ${obsCount} connection(s) recorded as baseline. Future runs flag new destinations.`
      : `**${obsCount}** unique destination(s) across ${runCount} run(s). Phase: ${phaseNote}.`;

    baselineSection = `
### 📊 Egress Baseline (run #${runCount})

> ${firstRunNote}${newDestsArr.length > 0 ? `\n> ⚠️ **${newDestsArr.length} new destination(s) flagged as potential supply chain deviation!**` : ''}

| Destination | Process Chain | Status |
|-------------|---------------|--------|
${destRows}
`;
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

  const tlsCount = stats ? (stats.tls_connections || 0) : '–';
  const uniqueDests = stats ? (stats.unique_destinations || 0) : '–';
  const blockedCount = stats ? (stats.blocked_connections || 0) : '–';

  const serverUrl = core.getState("serverUrl") || "https://api.codexsecurity.io";
  const dashboardUrl = `${serverUrl}/projects`;

  const md = `
## ${alertIcon} O3 Security ROC Agent — Security Summary

**Workflow:** \`${workflow}\` | **Job:** \`${job}\` | **Run:** [#${runId}](https://github.com/${repo}/actions/runs/${runId})

| Metric | Value |
|--------|-------|
| TLS/SSL connections captured | **${tlsCount}** |
| Unique egress destinations | **${uniqueDests}** |
| Connections blocked | **${blockedCount}** |
| FIM file violations | **${fimEvents ? fimEvents.length : '-'}** |
| Egress policy | \`${egressPolicy || 'audit'}\` |

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
    // 1. Kill egress interceptor first (flush any pending writes)
    const interceptorPid = core.getState('interceptorPid');
    if (interceptorPid) {
      try { process.kill(parseInt(interceptorPid), 'SIGTERM'); } catch (_) { }
      await sleep(500);
    }
    // 2. Signal ROC binary to flush summary
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


  // 4. Read FIM events — passed to uploadPipelineVuln as fallback until binary ships FIM upload in Docker image
  const fimEvents = await readFIMEvents();
  if (fimEvents.length > 0) {
    core.warning(`[FIM] ⚠️  ${fimEvents.length} file integrity violation(s) detected during build!`);
    core.info('\n🔍 File Integrity Violations:');
    core.info('─'.repeat(60));
    fimEvents.slice(0, 20).forEach(e => {
      const proc = e.comm ? ` [${e.comm}]` : '';
      const action = e.action || e.event_type || 'modified';
      core.info(`  🔍 ${action.toUpperCase()} ${e.path || e.filename || '?'}${proc}`);
    });
    if (fimEvents.length > 20) core.info(`  … and ${fimEvents.length - 20} more FIM events`);
    core.info('─'.repeat(60));
    // Binary now handles FIM upload via UploadFIMFindings at SIGTERM shutdown.
    // uploadPipelineVuln below will include fim_events as a fallback.
  }

  // 5. Run CI baseline analysis via GraphQL (IngestCIBaseline)
  //    Sends all egress destinations + FIM events observed this run.
  //    Backend tracks learning/active phase and creates deviation vulns.
  let baselineReport = null;
  if (core.getInput("baseline_enabled") !== "false" && apiKey) {
    try {
      const egressLog = "/tmp/roc-egress-log.jsonl";
      const egressDestinations = [];
      if (await fs.pathExists(egressLog)) {
        const content = await fs.readFile(egressLog, "utf8");
        for (const line of content.split("\n").filter(l => l.trim())) {
          try {
            const ev = JSON.parse(line);
            if (ev.secrets === true) continue; // skip secret-only markers
            const host = ev.domain || ev.ip || null;
            const portStr = ev.port ? String(ev.port) : '443';
            if (!host) continue;
            egressDestinations.push({
              key: `${host}:${portStr}`,
              host,
              port: portStr,
              protocol: ev.protocol || 'tcp',
              severity: ev.severity || 'info',
              comm: ev.comm || null,
              cmdline: ev.cmdline || null,
              parent_comm: ev.parent_comm || null,
              source: 'egress_interceptor',
            });
          } catch (_) { /* skip malformed */ }
        }
      }

      // Also include binary-captured destinations from traffic_runtime_data
      // (binary runs inside Docker, writes to API — not to host JSONL)
      // For now we rely on egress-interceptor JSONL for host-side egress.
      // When binary sends all flows (not just secret ones), this will auto-populate.

      const fimObs = fimEvents.map(e => ({
        key: e.path || e.filename || e.key || null,
        path: e.path || e.filename || null,
        event_type: e.event_type || e.type || 'write',
        severity: e.severity || 'medium',
        comm: e.comm || null, cmdline: e.cmdline || null,
        parent_comm: e.parent_comm || null,
      })).filter(o => o.key);

      const gqlEndpoint = serverUrl.endsWith('/graphql') ? serverUrl : `${serverUrl.replace(/\/$/, '')}/graphql`;
      const ingestMutation = `
        mutation IngestCIBaseline(
          $project_name: String, $session_id: String,
          $repo: String!, $job: String!, $branch: String!, $run_id: String!,
          $run_number: String, $workflow: String, $actor: String, $sha: String,
          $egress: JSON, $fim_events: JSON
        ) {
          IngestCIBaseline(
            project_name: $project_name session_id: $session_id
            repo: $repo job: $job branch: $branch run_id: $run_id
            run_number: $run_number workflow: $workflow actor: $actor sha: $sha
            egress: $egress fim_events: $fim_events
          ) {
            status phase run_count observations deviations new_destinations vuln_id
          }
        }
      `;

      // Load step context — written by index.js; fallback to env vars
      let stepCtx = {};
      try {
        if (await fs.pathExists("/tmp/roc-step-context.json")) {
          stepCtx = await fs.readJson("/tmp/roc-step-context.json");
        }
      } catch (_) { }

      core.info(`[Baseline] ${egressDestinations.length} egress connections, ${fimObs.length} FIM events to process`);
      core.info(`[Baseline] ${new Set(egressDestinations.map(d => d.key)).size} unique egress destinations after dedup`);

      // If post.js has NO egress data (binary captures inside Docker → JSONL empty) AND no FIM events,
      // the binary already called IngestCIBaseline at shutdown with the real observations.
      // Skip the call to avoid creating a duplicate run with 0 observations.
      // Instead, query the latest baseline run to get the real stats for step summary.
      if (egressDestinations.length === 0 && fimObs.length === 0) {
        core.info('[Baseline] No host-side egress data — binary already ingested via FlushEgressBaseline. Querying latest run for stats.');
        try {
          const runCtx = stepCtx.repository || process.env.GITHUB_REPOSITORY || '';
          const runJob = stepCtx.job || process.env.GITHUB_JOB || 'default';
          const refStr = stepCtx.ref || process.env.GITHUB_REF || '';
          const branchFallback = stepCtx.branch || process.env.GITHUB_REF_NAME
            || (refStr.startsWith('refs/heads/') ? refStr.slice('refs/heads/'.length) : refStr) || 'main';
          const latestRunResp = await axios.post(gqlEndpoint, {
            query: `query GetBaselineRuns($repo: String, $job: String, $branch: String, $limit: Int) {
              GetBaselineRuns(repo: $repo, job: $job, branch: $branch, limit: $limit) {
                data { phase run_id total_run_count observations_count deviations_count ran_at }
              }
            }`,
            variables: { repo: runCtx, job: runJob, branch: branchFallback, limit: 1 },
          }, {
            headers: { authorization: `apiKey ${apiKey}`, 'Content-Type': 'application/json' },
            timeout: 8000,
          });
          const latestRun = latestRunResp.data?.data?.GetBaselineRuns?.data?.[0];
          if (latestRun) {
            baselineReport = {
              phase: latestRun.phase,
              firstRun: latestRun.total_run_count <= 1,
              runCount: latestRun.total_run_count,
              observations: latestRun.observations_count || 0,
              deviations: latestRun.deviations_count || 0,
              newDestinations: [],
              high_severity_deviations: [],
              knownDestinations: [],
              vuln_id: null,
            };
            core.info(`[Baseline] Latest run fetched: phase=${latestRun.phase}, run #${latestRun.total_run_count}, ${latestRun.observations_count || 0} observations`);

            // Also fetch the actual observed entries so we can display them
            try {
              const entriesResp = await axios.post(gqlEndpoint, {
                query: `query GetBaselineEntries($repo: String, $job: String, $branch: String, $limit: Int) {
                  GetBaselineEntries(repo: $repo, job: $job, branch: $branch, limit: $limit) {
                    data { key type severity status comm occurrence_count last_seen }
                  }
                }`,
                variables: { repo: runCtx, job: runJob, branch: branchFallback, limit: 50 },
              }, {
                headers: { authorization: `apiKey ${apiKey}`, 'Content-Type': 'application/json' },
                timeout: 8000,
              });
              const entries = entriesResp.data?.data?.GetBaselineEntries?.data || [];
              const egressEntries = entries.filter(e => e.type !== 'file_modification');
              baselineReport.knownDestinations = egressEntries.map(e => e.key);
              baselineReport.egressEntries = egressEntries;

              if (egressEntries.length > 0) {
                core.info(`\n📡 Egress Destinations (${egressEntries.length} unique):`);
                core.info('─'.repeat(60));
                egressEntries.forEach(e => {
                  const proc = e.comm ? ` [${e.comm}]` : '';
                  const count = e.occurrence_count > 1 ? ` ×${e.occurrence_count}` : '';
                  const badge = e.status === 'trusted' ? '✅' : e.status === 'new' ? '⚠️ NEW' : '🔵';
                  core.info(`  ${badge} ${e.key}${proc}${count}`);
                });
                core.info('─'.repeat(60));
              }
            } catch (eErr) {
              core.debug(`[Baseline] Could not fetch entries: ${eErr.message}`);
            }

            // Query secret findings for this run from pipeline security vulns (server-side filtered)
            try {
              const runId = stepCtx.run_id || process.env.GITHUB_RUN_ID || '';
              const secResp = await axios.post(gqlEndpoint, {
                query: `query GetSecretVulns($run_id: String, $limit: Int, $page: Int) {
                  GetPipelineSecurityVulns(run_id: $run_id, limit: $limit, page: $page) {
                    totalCount
                    data { pipeline_context }
                  }
                }`,
                variables: { run_id: runId, limit: 20, page: 1 },
              }, {
                headers: { authorization: `apiKey ${apiKey}`, 'Content-Type': 'application/json' },
                timeout: 8000,
              });
              const secData = secResp.data?.data?.GetPipelineSecurityVulns;
              const vulns = secData?.data || [];
              core.info(`[Secrets] Query returned ${vulns.length}/${secData?.totalCount ?? '?'} vulns for run ${runId}`);
              const secretVulns = vulns.filter(v => {
                const ctx = v.pipeline_context;
                if (!ctx) return false;
                // Has secrets in the top-level secrets array (new format)
                const hasSecrets = Array.isArray(ctx.secrets) && ctx.secrets.length > 0;
                // OR has captures with non-empty secrets (old format)
                const hasCaptures = Array.isArray(ctx.captures) &&
                  ctx.captures.some(c => Array.isArray(c.secrets) && c.secrets.length > 0);
                return hasSecrets || hasCaptures;
              });
              if (secretVulns.length > 0) {
                const totalSecrets = secretVulns.reduce((sum, v) => {
                  const ctx = v.pipeline_context;
                  return sum + (Array.isArray(ctx?.secrets) ? ctx.secrets.length : 1);
                }, 0);
                baselineReport.secretsFound = totalSecrets;
                core.warning(`[Secrets] 🚨 ${totalSecrets} secret(s) in ${secretVulns.length} finding(s) for run ${runId}`);
              }
            } catch (sErr) {
              core.warning(`[Baseline] Could not query secrets: ${sErr.message}`);
            }
          }
        } catch (qErr) {
          core.debug(`[Baseline] Could not query latest run: ${qErr.message}`);
        }
      } else {
        // Host-side egress or FIM data available — call IngestCIBaseline directly
        const ref = stepCtx.ref || process.env.GITHUB_REF || '';
        const branchName = stepCtx.branch
          || process.env.GITHUB_REF_NAME
          || (ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ref)
          || 'main';

        const resp = await axios.post(gqlEndpoint, {
          query: ingestMutation,
          variables: {
            project_name: stepCtx.repository || process.env.GITHUB_REPOSITORY || '',
            session_id: process.env.GITHUB_RUN_ID ? `${process.env.GITHUB_REPOSITORY}_${process.env.GITHUB_RUN_ID}` : null,
            repo: stepCtx.repository || process.env.GITHUB_REPOSITORY || '',
            job: stepCtx.job || process.env.GITHUB_JOB || 'default',
            branch: branchName,
            run_id: stepCtx.run_id || process.env.GITHUB_RUN_ID || 'unknown',
            run_number: String(stepCtx.run_number || process.env.GITHUB_RUN_NUMBER || ''),
            workflow: stepCtx.workflow || process.env.GITHUB_WORKFLOW || '',
            actor: stepCtx.actor || process.env.GITHUB_ACTOR || '',
            sha: stepCtx.sha || process.env.GITHUB_SHA || '',
            egress: egressDestinations,
            fim_events: fimObs,
          },
        }, {
          headers: { authorization: `apiKey ${apiKey}`, 'Content-Type': 'application/json' },
          timeout: 15000,
        });

        const result = resp.data?.data?.IngestCIBaseline;
        if (result) {
          const newDests = result.new_destinations || [];
          baselineReport = {
            phase: result.phase,
            firstRun: result.run_count <= 1,
            runCount: result.run_count,
            observations: result.observations,
            deviations: result.deviations,
            newDestinations: newDests,
            high_severity_deviations: newDests.map(d => ({ key: d, type: 'egress', severity: 'medium' })),
            vuln_id: result.vuln_id,
          };
          core.info(`[Baseline] Ingested: phase=${result.phase}, run #${result.run_count}, ${result.observations} observations, ${result.deviations} deviation(s)`);
          if (newDests.length > 0) {
            core.warning(`[Baseline] ⚠️  ${newDests.length} new egress destination(s): ${newDests.join(', ')}`);
          } else if (!baselineReport.firstRun) {
            core.info('[Baseline] ✅ All egress matches baseline — no new connections');
          }
        }
      }
    } catch (e) {
      core.warning(`[Baseline] Analysis failed (non-fatal): ${e.message}`);
    }
  }

  // 6. Read stats + write GitHub Step Summary
  //    readSummaryStats tries: /tmp/roc-summary.json → egress JSONL → API query
  //    If all fail (binary captures inside Docker, no host JSONL), fall back to
  //    baseline observations from IngestCIBaseline response (which has the real count).
  let stats = await readSummaryStats(apiKey, serverUrl);
  if (!stats && baselineReport && baselineReport.observations != null) {
    // Synthesize from baseline data — binary recorded N unique TLS connections
    stats = {
      tls_connections: baselineReport.observations,
      unique_destinations: baselineReport.observations,
      secrets_found: baselineReport.secretsFound || 0, // populated by GetPipelineSecurityVulns query
      blocked_connections: 0,
      synthesized_from_baseline: true,
    };
    core.info(`[SummaryStat] Synthesized: ${baselineReport.observations} connections, ${stats.secrets_found} secret(s)`);
  }
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
