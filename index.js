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
      "-v", "/tmp:/tmp",          // shares /tmp/roc-step-context.json + policy YAML + fim-log
      // Mount the workspace at the SAME path so inotify can watch host source files
      // (without this the GITHUB_WORKSPACE path doesn't exist inside the container)
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

    // File integrity monitoring
    // Mount the workspace at the SAME path so the binary's inotify can watch host files.
    // The root filesystem is mounted at /host:ro, but the binary uses the original path
    // directly — so we need an explicit rw bind-mount of the workspace.
    const workspace = process.env.GITHUB_WORKSPACE;
    if (workspace) {
      // Insert the volume mount BEFORE the image name in dockerArgs
      // (dockerArgs already has the image at position -3 from end: [image, "all", "-m", "text"])
      const imgIdx = dockerArgs.indexOf(dockerImage);
      if (imgIdx !== -1) {
        dockerArgs.splice(imgIdx, 0, "-v", `${workspace}:${workspace}:rw`);
      }
      dockerArgs.push("--workspace", workspace);
      core.info(`[FIM] Watching workspace: ${workspace}`);
    }
    dockerArgs.push("--fim-log", "/tmp/roc-fim-events.jsonl");

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

    // ── Spawn container ───────────────────────────────────────────────────
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
        [interceptorPath, '/tmp/roc-egress-log.jsonl', '/tmp/roc-fim-events.jsonl', workspace || ''],
        {
          detached: true,
          stdio: ['ignore', iOut, iOut],
          env: { ...process.env, GITHUB_WORKSPACE: workspace || '' },
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

  } catch (error) {
    core.setFailed(`ROC Agent failed to start: ${error.message}`);
  }
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
