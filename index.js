const core = require("@actions/core");
const fs = require("fs-extra");
const { spawn, execSync } = require("child_process");

async function run() {
  try {
    core.info("Starting O3 Security ROC Agent...");

    // Write CI/CD step context for per-step event tagging inside the container
    const stepContext = {
      step: process.env.GITHUB_ACTION || "",
      job: process.env.GITHUB_JOB || "",
      workflow: process.env.GITHUB_WORKFLOW || "",
      run_id: process.env.GITHUB_RUN_ID || "",
      run_number: process.env.GITHUB_RUN_NUMBER || "",
      sha: process.env.GITHUB_SHA || "",
      ref: process.env.GITHUB_REF || "",
      actor: process.env.GITHUB_ACTOR || "",
      repository: process.env.GITHUB_REPOSITORY || "",
      runner_name: process.env.RUNNER_NAME || "",
      runner_os: process.env.RUNNER_OS || "",
      timestamp: Date.now(),
    };
    await fs.outputJson("/tmp/roc-step-context.json", stepContext);
    core.info(`CI/CD context: repo=${stepContext.repository} job=${stepContext.job}`);

    // ── Inputs ────────────────────────────────────────────────────────────
    const apiKey = core.getInput("api_key");
    const serverUrl = core.getInput("server_url") || "https://api.codexsecurity.io";
    const projectName = core.getInput("project_name");
    // Inline policy (open-source / no-dashboard mode)
    const policy = core.getInput("policy") || "audit";
    const allowedDomains = core.getInput("allowed_domains") || "";
    const allowedIPs = core.getInput("allowed_ips") || "";
    const allowedCIDRs = core.getInput("allowed_cidrs") || "";
    // Secret scanning
    const patterns = core.getInput("patterns");
    // SIEM
    const splunkUrl = core.getInput("splunk_url");
    const splunkToken = core.getInput("splunk_token");
    const esUrl = core.getInput("es_url");
    const esIndex = core.getInput("es_index");
    const esUser = core.getInput("es_user");
    const esPass = core.getInput("es_pass");
    // Mode
    const printOnly = core.getInput("print_only") === "true";
    const debug = core.getInput("debug") === "true";
    const dockerImage = core.getInput("docker_image") || "public.ecr.aws/f9o7b7m0/roc";
    // KAYO runtime security agent
    const runtimeSecurity = core.getInput("runtime_security") === "true";
    const kayoImage = core.getInput("runtime_security_image") || "public.ecr.aws/f9o7b7m0/kayo:latest";

    // ── Inline policy YAML ────────────────────────────────────────────────
    // Convert action inputs to the inline policy YAML and pass to the container.
    let policyFileArg = [];
    const hasInlinePolicy = Boolean(policy !== "audit" || allowedDomains || allowedIPs || allowedCIDRs);
    if (hasInlinePolicy) {
      const parseLine = (raw) =>
        raw.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
      const policyYAML = buildPolicyYAML(policy, parseLine(allowedDomains), parseLine(allowedIPs), parseLine(allowedCIDRs));
      const policyPath = "/tmp/roc-inline-policy.yaml";
      await fs.writeFile(policyPath, policyYAML, "utf8");
      policyFileArg = ["--policy-file", policyPath];
      core.info(`Inline policy: mode=${policy} domains=${parseLine(allowedDomains).length} ips=${parseLine(allowedIPs).length} cidrs=${parseLine(allowedCIDRs).length}`);
    }

    // ── Docker args ───────────────────────────────────────────────────────
    const dockerArgs = [
      "run", "-d",
      "--privileged",
      "--pid=host",
      "--net=host",
      "-v", "/home:/home:ro",
      "-v", "/:/host:ro",
      "-v", "/sys:/sys:ro",
      "-v", "/proc:/proc:ro",
      "-v", "/lib:/lib:ro",
      "-v", "/usr:/usr:ro",
      "-v", "/etc/ld.so.cache:/etc/ld.so.cache:ro",
      "-v", "/var/run/docker.sock:/var/run/docker.sock",
      "-v", "/run/containerd/containerd.sock:/run/containerd/containerd.sock",
      "-v", "/var/lib/docker:/var/lib/docker:ro",
      "-v", "/opt:/opt:ro",
      "-v", "/snap:/snap:ro",
      "-v", "/root:/root:ro",
      "-v", "/tmp:/tmp",          // shares /tmp/roc-step-context.json + policy YAML
      // CI/CD env vars for event tagging
      "-e", `GITHUB_REPOSITORY=${stepContext.repository}`,
      "-e", `GITHUB_RUN_ID=${stepContext.run_id}`,
      "-e", `GITHUB_RUN_NUMBER=${stepContext.run_number || process.env.GITHUB_RUN_NUMBER || ''}`,
      "-e", `GITHUB_JOB=${stepContext.job}`,
      "-e", `GITHUB_WORKFLOW=${stepContext.workflow}`,
      "-e", `GITHUB_SHA=${stepContext.sha}`,
      "-e", `GITHUB_ACTOR=${stepContext.actor}`,
      "-e", `GITHUB_REF=${process.env.GITHUB_REF || ''}`,
      "-e", `GITHUB_REF_NAME=${process.env.GITHUB_REF_NAME || stepContext.branch || ''}`,
      "-e", `RUNNER_NAME=${stepContext.runner_name}`,

      dockerImage,
      "all",
      "-m", "text",
    ];

    // Add API credentials if provided
    if (apiKey) dockerArgs.push("--api-key", apiKey);
    if (serverUrl) dockerArgs.push("--server-url", serverUrl);

    // project_name defaults to GITHUB_REPOSITORY so UploadTrafficRuntimeData
    // always knows which project to associate captures with.
    const effectiveProject = projectName || stepContext.repository;
    if (effectiveProject) dockerArgs.push("--project", effectiveProject);

    // --identifier lets the DPI binary fetch API patterns from the backend.
    const repoUrl = stepContext.repository
      ? `https://github.com/${stepContext.repository}`
      : "";
    if (repoUrl) dockerArgs.push("--identifier", repoUrl);

    // DEBUG: Print key DPI launch params so we can trace upload failures
    core.info(`[DEBUG] DPI launch params:`);
    core.info(`  api_key_set=${!!apiKey}  api_key_prefix=${apiKey ? apiKey.slice(0, 8) + '...' : '(none)'}`);
    core.info(`  server_url=${serverUrl}`);
    core.info(`  effective_project=${effectiveProject || '(none)'}`);
    core.info(`  identifier=${repoUrl || '(none)'}`);
    core.info(`  patterns_input=${patterns || '(none)'}`);

    // Inline policy file
    dockerArgs.push(...policyFileArg);

    // Secret scanning patterns
    if (patterns) dockerArgs.push("--pattern", await resolvePatterns(patterns));


    // Egress log for automated baseline (post.js reads this)
    dockerArgs.push("--egress-log", "/tmp/roc-egress-log.jsonl");

    if (splunkUrl) dockerArgs.push("--splunk-url", splunkUrl);
    if (splunkToken) dockerArgs.push("--splunk-token", splunkToken);
    if (esUrl) dockerArgs.push("--es-url", esUrl);
    if (esIndex) dockerArgs.push("--es-index", esIndex);
    if (esUser) dockerArgs.push("--es-user", esUser);
    if (esPass) dockerArgs.push("--es-pass", esPass);
    if (printOnly) dockerArgs.push("--print-only");
    if (debug) dockerArgs.push("--debug");

    // ── Pull image with retry (ECR Public rate-limits unauthenticated pulls) ─
    core.info(`Pulling ROC image: ${dockerImage}`);
    let pulled = false;
    for (let attempt = 1; attempt <= 3; attempt++) {
      const pullResult = await new Promise(resolve => {
        const p = require('child_process').spawnSync(
          'sudo', ['docker', 'pull', dockerImage],
          { stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000 }
        );
        resolve({ ok: p.status === 0, stderr: (p.stderr || '').toString() });
      });
      if (pullResult.ok) { pulled = true; break; }
      const isRateLimit = pullResult.stderr.includes('toomanyrequests') || pullResult.stderr.includes('Rate exceeded');
      if (isRateLimit && attempt < 3) {
        const wait = attempt * 15;
        core.warning(`[Docker] ECR rate limit hit — retrying pull in ${wait}s (attempt ${attempt}/3)…`);
        await new Promise(r => setTimeout(r, wait * 1000));
      } else {
        core.warning(`[Docker] Pull failed (attempt ${attempt}/3): ${pullResult.stderr.trim().slice(0, 200)}`);
        if (attempt === 3) core.setFailed(`Failed to pull ROC image after 3 attempts: ${pullResult.stderr.trim().slice(0, 200)}`);
      }
    }

    // ── Spawn container ───────────────────────────────────────────────────
    // Pre-create shared /tmp log files with world-writable perms so the binary
    // inside Docker can write to them (binary runs as root, but files created by
    // a previous run may be owned by runner user with 644 → EACCES).
    for (const logFile of ['/tmp/roc-egress-log.jsonl']) {
      try {
        // Truncate existing file or create new one, then set 666 so any user can write
        const fd = require('fs').openSync(logFile, 'w');
        require('fs').closeSync(fd);
        require('fs').chmodSync(logFile, 0o666);
      } catch (_) { /* best-effort */ }
    }

    const outStream = fs.openSync("/tmp/roc-stdout.log", "a");
    const errStream = fs.openSync("/tmp/roc-stderr.log", "a");

    core.info(`Starting ROC container (image: ${dockerImage}, egress: ${policy})`);
    const rocProcess = spawn("sudo", ["docker", ...dockerArgs], {
      detached: true,
      stdio: ["ignore", outStream, errStream],
    });
    rocProcess.unref();

    core.saveState("rocPid", rocProcess.pid.toString());
    core.saveState("dockerImage", dockerImage);
    core.saveState("egressPolicy", policy);
    core.saveState("serverUrl", serverUrl);
    core.setOutput("roc_pid", rocProcess.pid.toString());

    // ── Spawn egress-interceptor (Node.js HTTP request capture) ──────────────
    // The roc binary captures TCP-level metadata (host/port/comm) but NOT HTTP
    // request details (method/URL/headers). The interceptor monkey-patches
    // Node's net/https/http to append full request info to the same JSONL log.
    try {
      // Use the ncc-bundled version (includes chokidar + all deps)
      // Falls back to raw source if bundle not present
      const bundlePath = require('path').join(__dirname, 'interceptor', 'index.js');
      const rawPath = require('path').join(__dirname, 'egress-interceptor.js');
      const fs = require('fs');
      const interceptorPath = fs.existsSync(bundlePath) ? bundlePath : rawPath;
      const iOut = fs.openSync('/tmp/roc-interceptor.log', 'a');
      const interceptorProc = spawn(
        process.execPath,
        [interceptorPath, '/tmp/roc-egress-log.jsonl'],
        {
          detached: true,
          stdio: ['ignore', iOut, iOut],
          env: { ...process.env },
        }
      );
      interceptorProc.unref();
      core.saveState('interceptorPid', String(interceptorProc.pid));
      core.info(`[Interceptor] HTTP capture running (PID: ${interceptorProc.pid}) from ${interceptorPath}`);
    } catch (e) {
      core.warning(`[Interceptor] Could not start: ${e.message}`);
    }


    // ── Health check ──────────────────────────────────────────────────────
    // Wait longer to account for image pull time on first run
    await sleep(8000);
    try {
      // Check running first, then exited (container may have crashed immediately)
      let cid = execSync(
        `sudo docker ps --filter "ancestor=${dockerImage}" --filter "status=running" --format "{{.ID}}" | head -1`,
        { encoding: "utf8" }
      ).trim();

      if (!cid) {
        // Grab it even if exited — we still want containerId for logs
        cid = execSync(
          `sudo docker ps -a --filter "ancestor=${dockerImage}" --format "{{.ID}}" | head -1`,
          { encoding: "utf8" }
        ).trim();
      }

      if (cid) {
        core.saveState("containerId", cid);
        // Check actual status
        const status = execSync(
          `sudo docker inspect --format='{{.State.Status}} (exit={{.State.ExitCode}})' ${cid} 2>/dev/null`,
          { encoding: "utf8" }
        ).trim();
        if (status.includes("running")) {
          core.info(`✅ ROC container running (ID: ${cid})`);
        } else {
          core.warning(`⚠️ ROC container exited (${status}) — printing docker logs:`);
          try {
            const dkLogs = execSync(`sudo docker logs ${cid} 2>&1`, { encoding: "utf8" });
            core.warning(dkLogs || "(no container output)");
          } catch (_) { }
        }
      } else {
        const stderr = await fs.readFile("/tmp/roc-stderr.log", "utf8").catch(() => "(no output)");
        core.warning(`ROC container not found. stderr:\n${stderr}`);
      }
    } catch (e) {
      core.warning(`Could not verify container status: ${e.message}`);
    }

    // ── KAYO runtime security agent (optional) ───────────────────────────
    if (runtimeSecurity) {
      await startKayoContainer({
        image: kayoImage,
        apiKey,
        serverUrl,
        projectName: effectiveProject,
        printOnly,
        debug,
      });
    }

  } catch (error) {
    core.setFailed(`ROC Agent failed to start: ${error.message}`);
  }
}

/**
 * Spawns the KAYO runtime security agent in a privileged container alongside
 * ROC. KAYO uses eBPF kprobes to monitor filesystem access, process exec, and
 * network egress on the GitHub Actions runner. Detections are uploaded to the
 * same O3 Security backend; rules are fetched from the backend by project name.
 */
async function startKayoContainer({ image, apiKey, serverUrl, projectName, printOnly, debug }) {
  core.info(`[KAYO] Starting runtime security agent (image: ${image})`);

  // Host directory for KAYO event log (mirrors what `--kayo-report-file` writes
  // inside the container).
  try {
    require('fs').mkdirSync('/tmp/kayo-events', { recursive: true });
    require('fs').chmodSync('/tmp/kayo-events', 0o777);
  } catch (_) { /* best-effort */ }

  // Pull image with retry (ECR Public rate-limits unauthenticated pulls).
  let pulled = false;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const pull = require('child_process').spawnSync(
      'sudo', ['docker', 'pull', image],
      { stdio: ['ignore', 'pipe', 'pipe'], timeout: 180_000 }
    );
    if (pull.status === 0) { pulled = true; break; }
    const stderr = (pull.stderr || '').toString();
    const isRateLimit = stderr.includes('toomanyrequests') || stderr.includes('Rate exceeded');
    if (isRateLimit && attempt < 3) {
      const wait = attempt * 15;
      core.warning(`[KAYO] ECR rate limit hit — retrying pull in ${wait}s (attempt ${attempt}/3)…`);
      await sleep(wait * 1000);
    } else {
      core.warning(`[KAYO] Pull failed (attempt ${attempt}/3): ${stderr.trim().slice(0, 200)}`);
      if (attempt === 3) {
        core.warning('[KAYO] Skipping runtime security — image pull failed after 3 attempts');
        return;
      }
    }
  }
  if (!pulled) return;

  // Tetragon's gRPC server (:54321) and health server (:6789) both default to
  // ports that may collide with other services on the runner. Override to be safe.
  // Volume set matches the production tetragon daemonset (see
  // examples/kayo-rules/deploy/daemonset.yaml in the tetragon repo). Without
  // /sys/fs/cgroup tetragon spams "Cgroup deployment mode unknown" and
  // disables advanced cgroup tracking; without an explicit BTF mount tetragon
  // can fail on runner images where /sys/kernel/btf/vmlinux is missing or at
  // a non-default path.
  const args = [
    'run', '-d',
    '--name', 'kayo',
    '--privileged',
    '--pid=host',
    '--network=host',
    '-v', '/sys/fs/bpf:/sys/fs/bpf',
    '-v', '/sys/kernel/debug:/sys/kernel/debug',
    '-v', '/sys/fs/cgroup:/sys/fs/cgroup:ro',
    '-v', '/sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro',
    '-v', '/proc:/procRoot:ro',
    '-v', '/tmp/kayo-events:/var/log/kayo',
    image,
    '/usr/bin/tetragon',
    '--bpf-lib=/var/lib/tetragon/',
    '--procfs=/procRoot',
    '--health-server-address=:7789',
    '--server-address=localhost:54322',
    '--bpf-dir=tetragon-kayo',
    '--enable-tracing-policy-crd=false',
    '--enable-pod-info=false',
    '--release-pinned-bpf=true',
    '--kayo-report-file=/var/log/kayo/events.jsonl',
    '--kayo-workers=8',
  ];
  if (serverUrl) args.push(`--kayo-server-url=${serverUrl}`);
  if (apiKey) args.push(`--kayo-apikey=${apiKey}`);
  if (projectName) args.push(`--kayo-project-name=${projectName}`);
  if (printOnly) args.push('--kayo-print-only');

  let containerId = '';
  try {
    const out = execSync(`sudo docker ${args.map(a => `'${a.replace(/'/g, "'\\''")}'`).join(' ')}`, {
      encoding: 'utf8',
      timeout: 60_000,
    }).trim();
    containerId = out.split('\n').pop().trim();
  } catch (e) {
    core.warning(`[KAYO] docker run failed: ${e.message}`);
    return;
  }

  core.saveState('kayoContainerId', containerId);
  core.saveState('kayoImage', image);
  core.setOutput('kayo_container_id', containerId);
  core.info(`[KAYO] Container started: ${containerId.slice(0, 12)}`);

  // ── Health check ──────────────────────────────────────────────────────
  // Tetragon's startup is heavy: BPF program load + verifier passes, BTF
  // discovery, sensor manager init, optional API rule fetch. On a cold
  // GitHub runner with no warm caches this takes ~10-20s. Poll until the
  // container settles (running or exited) rather than waiting blindly.
  let finalStatus = '';
  for (let i = 0; i < 12; i++) {
    await sleep(2000);
    try {
      finalStatus = execSync(
        `sudo docker inspect --format='{{.State.Status}} (exit={{.State.ExitCode}})' ${containerId} 2>/dev/null`,
        { encoding: 'utf8' }
      ).trim();
    } catch (_) { finalStatus = 'unknown'; }
    if (finalStatus.includes('exited') || finalStatus.includes('dead')) break;
    // Already running and we've waited at least 4s → success
    if (finalStatus.includes('running') && i >= 1) break;
  }

  if (finalStatus.includes('running')) {
    core.info(`✅ KAYO container running (ID: ${containerId.slice(0, 12)}, status: ${finalStatus})`);
    return;
  }

  // Container is not running. Dump full logs line-by-line via core.info so
  // GitHub doesn't truncate them (core.warning emits one-line annotations
  // which the UI clips at ~4KB — that's why the multi-KB tetragon config
  // dump showed up cut off as "...export-file-compress:fal" in earlier runs).
  core.warning(`⚠️ KAYO container is not running (status: ${finalStatus || 'unknown'})`);
  let logsText = '';
  try {
    logsText = execSync(`sudo docker logs ${containerId} 2>&1`, {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (e) {
    core.info(`could not read logs: ${e.message}`);
  }
  core.info('────────── KAYO docker logs (full) ──────────');
  if (logsText.trim()) {
    for (const line of logsText.split('\n')) core.info(line);
  } else {
    core.info('(no container output)');
  }
  core.info('────────── end KAYO docker logs ──────────');

  // Parse the actual fatal line and give a targeted hint. tetragon logs the
  // fatal as: level=error msg="Failed to execute tetragon" error="<reason>"
  const fatalMatch = logsText.match(/level=error msg="Failed to execute tetragon" error="([^"]+)"/);
  const fatal = fatalMatch ? fatalMatch[1] : '';
  if (fatal) core.warning(`[KAYO] fatal: ${fatal}`);
  const hint = diagnoseKayoFatal(fatal, logsText);
  if (hint) core.info(`[KAYO] hint: ${hint}`);
}

// diagnoseKayoFatal maps the most common tetragon/kayo startup failures to
// a one-line operator hint. Returns "" when nothing matches.
function diagnoseKayoFatal(fatal, logs) {
  if (!fatal && !logs) return '';
  const f = (fatal || '').toLowerCase();
  if (f.includes('insufficient permissions') || f.includes('read_runtime')) {
    return 'The provided api_key is missing the READ_RUNTIME scope on the backend. Grant the key access to runtime security rules for this project.';
  }
  if (f.includes('fetch rules') && f.includes('no rules')) {
    return 'The project has no runtime security rules registered on the backend. Add rules in the O3 Security dashboard for project_name then re-run.';
  }
  if (f.includes('btf')) {
    return 'BTF (kernel type info) is missing on the runner. The mount of /sys/kernel/btf/vmlinux is required and the kernel must expose it.';
  }
  if (f.includes('failed to load') && f.includes('bpf')) {
    return 'BPF program load rejected by the kernel verifier. Check the runner kernel version; tetragon needs ≥5.10.';
  }
  if (f.includes('bind: address already in use') || f.includes('listen tcp')) {
    return 'A port collision (gRPC :54322 or health :7789). Likely another tetragon process on the runner — should not normally happen on hosted runners.';
  }
  if (f.includes('permission denied') && f.includes('/sys/fs/bpf')) {
    return '/sys/fs/bpf is not writable. Ensure --privileged and that the host has the BPF filesystem mounted.';
  }
  if (logs.includes('debugfs') && logs.includes('not mounted')) {
    return '/sys/kernel/debug is not mounted on the host. KAYO needs it for some kprobe attach paths.';
  }
  return '';
}

/**
 * Resolves the `patterns` input to a file path the container can read.
 * Accepts either:
 *   1. A file path:          .github/roc-patterns.yaml
 *   2. Inline YAML content:  - id: aws_key\n  regex: 'AKIA...'
 *
 * Inline content is detected by the presence of a newline or a leading '-'.
 * It is normalised to the full patterns: [...] format and written to a temp file.
 */
async function resolvePatterns(input) {
  const trimmed = input.trim();
  const isInline = trimmed.includes("\n") || trimmed.startsWith("-") || trimmed.startsWith("patterns:");
  if (!isInline) {
    // It's a file path — pass through as-is
    return input;
  }

  // Inline YAML — normalise to patterns: [...] if not already
  let yaml = trimmed;
  if (!yaml.startsWith("patterns:")) {
    // Indent each line by 2 spaces and add the top-level key
    yaml = "patterns:\n" + yaml.split("\n").map(l => "  " + l).join("\n");
  }

  const tmpPath = "/tmp/roc-inline-patterns.yaml";
  await fs.writeFile(tmpPath, yaml + "\n", "utf8");
  core.info(`Inline patterns written to ${tmpPath}`);
  return tmpPath;
}

function buildPolicyYAML(policy, domains, ips, cidrs) {
  const lines = [`policy: ${policy}`, "whitelist:"];
  if (domains.length > 0) {
    lines.push("  domains:");
    domains.forEach(d => lines.push(`    - ${d}`));
  }
  if (ips.length > 0) {
    lines.push("  ips:");
    ips.forEach(ip => lines.push(`    - ${ip}`));
  }
  if (cidrs.length > 0) {
    lines.push("  cidrs:");
    cidrs.forEach(c => lines.push(`    - ${c}`));
  }
  return lines.join("\n") + "\n";
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

run();
