const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs-extra");
const { spawn } = require("child_process");

async function run() {
  try {
    core.info("Starting ROC Action...");

    const watchDir = core.getInput("watch");
    if (watchDir) {
      core.info(`Ensuring watch directory exists at ${watchDir}`);
      await fs.ensureDir(watchDir);
    }

    // Get required inputs
    const serverUrl = core.getInput("server_url", { required: true });
    const apiKey = core.getInput("api_key", { required: true });
    const projectName = core.getInput("project_name", { required: true });

    // Construct docker run command
    const dockerArgs = [
      "run",
      "-d",
      "--privileged",
      "--pid=host",
      "--net=host",
      "-v", "/:/host:ro",
      "-v", "/sys:/sys:ro",
      "-v", "/proc:/proc:ro",
      "-v", "/lib:/lib:ro",
      "-v", "/usr:/usr:ro",
      "-v", "/etc/ld.so.cache:/etc/ld.so.cache:ro",
      "-v", "/etc/ld.so.conf:/etc/ld.so.conf:ro",
      "-v", "/etc/ld.so.conf.d:/etc/ld.so.conf.d:ro",
      "-v", "/var/run/docker.sock:/var/run/docker.sock",
      "-v", "/run/containerd/containerd.sock:/run/containerd/containerd.sock",
      "-v", "/var/lib/docker:/var/lib/docker:ro",
      "-v", "/opt:/opt:ro",
      "-v", "/snap:/snap:ro",
      "-v", "/root:/root:ro",
      "hanshal785/youreded",
      "all",
      "-m", "text",
      "--project", projectName,
      "--api-key", apiKey,
      "--server-url", serverUrl,
    ];

    // Add optional arguments
    const pcap = core.getInput("pcap");
    if (pcap) {
      dockerArgs.push("--pcap", pcap);
    }

    if (watchDir) {
      dockerArgs.push("--watch", watchDir);
    }

    const patterns = core.getInput("patterns");
    if (patterns) {
      dockerArgs.push("--patterns", patterns);
    }

    const networkConfig = core.getInput("network_config");
    if (networkConfig) {
      dockerArgs.push("--network-config", networkConfig);
    }

    const interface = core.getInput("interface");
    if (interface) {
      dockerArgs.push("--interface", interface);
    }

    const sslLib = core.getInput("ssl_lib");
    if (sslLib) {
      dockerArgs.push("--ssl-lib", sslLib);
    }

    const sslVersion = core.getInput("ssl_version");
    if (sslVersion) {
      dockerArgs.push("--ssl-version", sslVersion);
    }

    const pksizeLim = core.getInput("pksize_lim");
    if (pksizeLim) {
      dockerArgs.push("--pksize-lim", pksizeLim);
    }

    const rotationInterval = core.getInput("rotation_interval");
    if (rotationInterval) {
      dockerArgs.push("--rotation-interval", rotationInterval);
    }

    const ecapOutputFolder = core.getInput("ecap_output_folder");
    if (ecapOutputFolder) {
      dockerArgs.push("--ecap-output-folder", ecapOutputFolder);
    }

    const source = core.getInput("source");
    if (source) {
      dockerArgs.push("--source", source);
    }

    const splunkUrl = core.getInput("splunk_url");
    if (splunkUrl) {
      dockerArgs.push("--splunk-url", splunkUrl);
    }

    const splunkToken = core.getInput("splunk_token");
    if (splunkToken) {
      dockerArgs.push("--splunk-token", splunkToken);
    }

    const esUrl = core.getInput("es_url");
    if (esUrl) {
      dockerArgs.push("--es-url", esUrl);
    }

    const esIndex = core.getInput("es_index");
    if (esIndex) {
      dockerArgs.push("--es-index", esIndex);
    }

    const esUser = core.getInput("es_user");
    if (esUser) {
      dockerArgs.push("--es-user", esUser);
    }

    const esPass = core.getInput("es_pass");
    if (esPass) {
      dockerArgs.push("--es-pass", esPass);
    }

    const config = core.getInput("config");
    if (config) {
      dockerArgs.push("--config", config);
    }

    // Add --print-only flag if enabled
    if (core.getInput("print_only") === true) {
      dockerArgs.push("--print-only");
    }

    if (core.getInput("debug") === "true") {
      dockerArgs.push("--debug");
    }

    // Log ROC output for debugging
    const outStream = fs.openSync("/tmp/roc-stdout.log", "a");
    const errStream = fs.openSync("/tmp/roc-stderr.log", "a");

    core.info(`Running command: sudo docker ${dockerArgs.join(" ")}`);

    // Spawn the process in the background (detached)
    const rocProcess = spawn("sudo", ["docker", ...dockerArgs], {
      detached: true,
      stdio: ["ignore", outStream, errStream],
    });

    // The action's main script can exit, but the child process will continue running.
    // The 'post' script will handle its termination.
    rocProcess.unref();

    // Save the PID to state for the post-action script to use
    core.saveState("rocPid", rocProcess.pid);
    core.setOutput("roc_pid", rocProcess.pid);
    core.info(
      `ROC process started in the background with PID: ${rocProcess.pid}`,
    );
  } catch (error) {
    core.setFailed(`Action failed with error: ${error.message}`);
  }
}

run();
