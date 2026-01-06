const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs-extra");
const { spawn } = require("child_process");

async function run() {
    try {
        core.info("Starting ROC Action...");

        // Get inputs from workflow
        const serverUrl = core.getInput("server_url", { required: true });
        const apiKey = core.getInput("api_key", { required: true });
        const projectIdentifier = core.getInput("project_identifier", {
            required: true,
        });
        const patternsFile = core.getInput("patterns_file", { required: true });
        const watchDir = core.getInput("watch_dir", { required: true });
        const rocBinaryPath = core.getInput("roc_binary_path", {
            required: true,
        });
        const setupDependencies =
            core.getInput("setup_dependencies") === "true";

        if (setupDependencies) {
            core.info("Setting up dependencies...");
            await exec.exec("sudo", ["apt-get", "update"]);
            await exec.exec("sudo", [
                "apt-get",
                "install",
                "-y",
                "curl",
                "iptables",
                "tshark",
                "libpcap-dev",
            ]);
        }

        core.info(`Ensuring watch directory exists at ${watchDir}`);
        await fs.ensureDir(watchDir);

        core.info(`Making ROC binary executable at ${rocBinaryPath}`);
        await exec.exec("chmod", ["+x", rocBinaryPath]);

        const rocArgs = [
            rocBinaryPath,
            "--server-url",
            serverUrl,
            "--api-key",
            apiKey,
            "--patterns",
            patternsFile,
            "--watch",
            watchDir,
            "-p",
            projectIdentifier,
        ];

        core.info(`Running command: sudo ${rocArgs.join(" ")}`);

        // Spawn the process in the background (detached)
        const rocProcess = spawn("sudo", rocArgs, {
            detached: true,
            stdio: "ignore", // Prevent hanging
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
