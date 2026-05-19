const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs-extra");
const { execSync } = require("child_process");
const axios = require("axios");
// Note: baseline analysis is now done via IngestCIBaseline GraphQL mutation (no REST import needed)

// Note: all vuln creation is handled by the Go binary via IngestCIBaseline.


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

// Note: All vuln creation (secrets + deviations) is now handled by the
// Go binary at shutdown via IngestCIBaseline. post.js is read-only: it queries
// stats and writes the GitHub Step Summary only.


// ----------------------------------------------------------------
// GitHub Step Summary writer
// ----------------------------------------------------------------
async function writeStepSummary(stats, egressPolicy, containerId, baselineReport) {
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

    const untrustedEntries = egressEntries.filter(e => e.status === 'untrusted');
    const newEntries = egressEntries.filter(e => e.status === 'new');
    if (untrustedEntries.length > 0) alertIcon = '🚨';
    if (newEntries.length > 0 && alertIcon === '✅') alertIcon = '⚠️';
    if (newDestsArr.length > 0 && alertIcon === '✅') alertIcon = '⚠️';

    // Process tree: parent_comm → comm
    const procTree = (e) => {
      if (e.parent_comm && e.comm && e.parent_comm !== e.comm) return `\`${e.parent_comm}\` → \`${e.comm}\``;
      if (e.comm) return `\`${e.comm}\``;
      return '–';
    };

    // Build a row for every entry, sorted NEW-first then UNTRUSTED then rest
    const sorted = [...egressEntries].sort((a, b) => {
      const rank = (e) => newDestsSet.has(e.key) || e.status === 'new' ? 0 : e.status === 'untrusted' ? 1 : 2;
      return rank(a) - rank(b);
    });

    const destRows = sorted.length > 0
      ? sorted.map(e => {
        const badge = newDestsSet.has(e.key)
          ? '⚠️ **NEW**'
          : e.status === 'untrusted'
            ? '🚫 **Untrusted**'
            : e.status === 'new'
              ? '⚠️ **NEW** (first seen)'
              : e.status === 'trusted'
                ? '✅ trusted'
                : '🔵 baseline';
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
| Egress policy | \`${egressPolicy || 'audit'}\` |

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
    // 2. Signal ROC container (ecapture PID 1) to flush and exit.
    //    rocPid is the PID of 'sudo docker run -d' which exits immediately, so
    //    kill -SIGINT rocPid is ineffective. Use 'docker kill' to send SIGINT
    //    directly to ecapture (container PID 1) and give it time to flush.
    if (containerId) {
      core.info(`Sending SIGINT to ROC container ${containerId} (ecapture PID 1)...`);
      try { await exec.exec("sudo", ["docker", "kill", "-s", "SIGINT", containerId]); } catch (_) { }
      // Wait for ecapture to complete FlushEgressBaseline HTTP call (8s timeout in binary)
      core.info("Waiting 12s for ecapture to flush egress baseline to backend...");
      await sleep(12000);
    }
    // 3. Stop container — give 10s grace period (binary should have exited after flush above)
    if (containerId) {
      core.info(`Stopping ROC container: ${containerId}`);
      try { await exec.exec("sudo", ["docker", "stop", "--timeout=10", containerId]); } catch (_) { }
    }
  } catch (e) {
    core.warning(`Error during ROC stop: ${e.message}`);
  }

  // ── KAYO runtime security teardown ─────────────────────────────────────
  // Mirrors the ROC stop sequence: SIGTERM → wait → docker stop. Tetragon's
  // graceful shutdown drains pinned BPF programs from /sys/fs/bpf so they
  // don't outlive the runner and fire against recycled PIDs on subsequent jobs.
  const kayoContainerId = core.getState("kayoContainerId") || "";
  if (kayoContainerId) {
    // Check whether the container is still running before signalling — if it
    // crashed during startup (eg. backend rejected the api_key) trying to
    // SIGTERM it produces a noisy "is not running" error from dockerd.
    let kayoRunning = false;
    try {
      const status = execSync(
        `sudo docker inspect --format='{{.State.Status}}' ${kayoContainerId} 2>/dev/null`,
        { encoding: "utf8" }
      ).trim();
      kayoRunning = (status === "running");
    } catch (_) { /* container may have been pruned */ }

    if (kayoRunning) {
      core.info(`KAYO: stopping runtime security container ${kayoContainerId.slice(0, 12)}`);
      try {
        await exec.exec("sudo", ["docker", "kill", "-s", "SIGTERM", kayoContainerId]);
        await sleep(5000);
        await exec.exec("sudo", ["docker", "stop", "--timeout=30", kayoContainerId]);
      } catch (e) {
        core.warning(`KAYO: error during stop: ${e.message}`);
      }
    } else {
      core.info(`KAYO: container ${kayoContainerId.slice(0, 12)} already exited — skipping kill/stop`);
    }
    // Print KAYO container logs and the event JSONL so detections show up in
    // the workflow output. maxBuffer bump (16MiB) avoids ENOBUFS on chatty
    // runs — tetragon dumps a multi-KB config block at startup.
    try {
      const kLogs = execSync(`sudo docker logs ${kayoContainerId} 2>&1`, {
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
      });
      const lines = kLogs.split("\n");
      const tail = lines.slice(-200).join("\n");
      core.info("── KAYO container logs (tail 200) ──");
      for (const l of tail.split("\n")) core.info(l);
    } catch (e) { core.info(`KAYO docker logs error: ${e.message}`); }
    try {
      if (await fs.pathExists("/tmp/kayo-events/events.jsonl")) {
        const events = await fs.readFile("/tmp/kayo-events/events.jsonl", "utf8");
        const count = events.trim() ? events.trim().split("\n").length : 0;
        core.info(`── KAYO detection events (${count}) ──`);
        for (const l of (events.trim() || "(no detections)").split("\n")) core.info(l);
      } else {
        core.info("── KAYO event log: NOT FOUND at /tmp/kayo-events/events.jsonl");
      }
    } catch (e) { core.info(`KAYO event log read error: ${e.message}`); }
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
    const psOut = execSync("sudo docker ps -a --format 'table {{.ID}}\\t{{.Image}}\\t{{.Status}}\\t{{.Names}}' 2>&1", {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    core.info("── docker ps -a ──");
    core.info(psOut || "(empty)");
  } catch (e) { core.info(`docker ps error: ${e.message}`); }

  // Docker logs from our container — large maxBuffer avoids ENOBUFS on a
  // chatty ROC container (ecapture can write tens of MB of TLS records).
  if (containerId) {
    try {
      const dockerLogs = execSync(`sudo docker logs ${containerId} 2>&1`, {
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
      });
      core.info(`── docker logs (${containerId}) ──`);
      core.info(dockerLogs || "(empty)");
    } catch (e) { core.info(`docker logs error: ${e.message}`); }
  }

  // All ROC /tmp files
  const tmpFiles = [
    "/tmp/roc-stdout.log",
    "/tmp/roc-stderr.log",
    "/tmp/roc-egress-log.jsonl",
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


  // 4. Run CI baseline analysis via GraphQL (IngestCIBaseline)
  //    Sends all egress destinations observed this run.
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

      const gqlEndpoint = serverUrl.endsWith('/graphql') ? serverUrl : `${serverUrl.replace(/\/$/, '')}/graphql`;
      const ingestMutation = `
        mutation IngestCIBaseline(
          $project_name: String, $session_id: String,
          $repo: String!, $job: String!, $branch: String!, $run_id: String!,
          $run_number: String, $workflow: String, $actor: String, $sha: String,
          $egress: JSON, $allowed_domains: [String]
        ) {
          IngestCIBaseline(
            project_name: $project_name session_id: $session_id
            repo: $repo job: $job branch: $branch run_id: $run_id
            run_number: $run_number workflow: $workflow actor: $actor sha: $sha
            egress: $egress allowed_domains: $allowed_domains
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

      core.info(`[Baseline] ${egressDestinations.length} egress connections to process`);
      core.info(`[Baseline] ${new Set(egressDestinations.map(d => d.key)).size} unique egress destinations after dedup`);

      // If post.js has NO egress data from the TCPMonitor JSONL, the binary may have
      // already sent data via IngestCIBaseline (FlushEgressBaseline at shutdown).
      // Query the latest baseline run for stats rather than calling IngestCIBaseline
      // with an empty payload.
      if (egressDestinations.length === 0) {
        core.info('[Baseline] No host-side TCP egress data in JSONL — querying latest run from backend for stats (binary sent TLS-level egress at shutdown).');
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
                  const badge = e.status === 'trusted' ? '✅' : e.status === 'untrusted' ? '🚫 UNTRUSTED' : e.status === 'new' ? '⚠️ NEW' : '🔵';
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
        // Host-side egress data available — call IngestCIBaseline directly
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
            allowed_domains: (core.getInput('allowed_domains') || '')
              .split('\n')
              .map(l => l.trim())
              .filter(l => l && !l.startsWith('#')),
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
  await writeStepSummary(stats, egressPolicy, containerId, baselineReport);

  // 7. Warn on secrets (binary already created the vuln via IngestCIBaseline at shutdown)
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
