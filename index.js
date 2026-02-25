const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs-extra");
const { spawn } = require("child_process");

async function run() {
  try {
    core.info("Starting ROC Action...");

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
      "public.ecr.aws/f9o7b7m0/roc",
      "all",
      "-m", "text",
      "--project", projectName,
      "--api-key", apiKey,
      "--server-url", serverUrl,
    ];

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
