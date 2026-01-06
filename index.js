const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs-extra");
const { spawn } = require("child_process");

async function run() {
    try {
        core.info("Starting ROC Action...");

        // Get inputs from workflow
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

        const watchDir = core.getInput("watch");
        if (watchDir) {
            core.info(`Ensuring watch directory exists at ${watchDir}`);
            await fs.ensureDir(watchDir);
        }

        core.info(`Making ROC binary executable at ${rocBinaryPath}`);
        await exec.exec("chmod", ["+x", rocBinaryPath]);

        // Construct arguments for the roc binary
        const rocArgs = [rocBinaryPath];

        const inputs = {
            "server-url": core.getInput("server_url", { required: true }),
            "api-key": core.getInput("api_key", { required: true }),
            "project-name": core.getInput("project_name", { required: true }),
            pcap: core.getInput("pcap"),
            watch: watchDir,
            patterns: core.getInput("patterns"),
            "network-config": core.getInput("network_config"),
            interface: core.getInput("interface"),
            "ssl-lib": core.getInput("ssl_lib"),
            "ssl-version": core.getInput("ssl_version"),
            "pksize-lim": core.getInput("pksize_lim"),
            "rotation-interval": core.getInput("rotation_interval"),
            "ecap-output-folder": core.getInput("ecap_output_folder"),
            source: core.getInput("source"),
            "splunk-url": core.getInput("splunk_url"),
            "splunk-token": core.getInput("splunk_token"),
            "es-url": core.getInput("es_url"),
            "es-index": core.getInput("es_index"),
            "es-user": core.getInput("es_user"),
            "es-pass": core.getInput("es_pass"),
            config: core.getInput("config"),
        };

        for (const [key, value] of Object.entries(inputs)) {
            if (value) {
                rocArgs.push(`--${key}`, value);
            }
        }

        if (core.getInput("debug") === "true") {
            rocArgs.push("--debug");
        }

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
