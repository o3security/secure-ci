const core = require("@actions/core");
const exec = require("@actions/exec");

async function cleanup() {
    try {
        const rocPid = core.getState("rocPid");
        if (rocPid) {
            core.info(`Stopping ROC process with PID: ${rocPid}`);
            // Use sudo to ensure permissions to kill the process started with sudo
            await exec.exec("sudo", ["kill", "-SIGINT", rocPid]);
            core.info(`Successfully sent SIGINT to ROC process ${rocPid}.`);
        } else {
            core.info("No ROC PID found, skipping cleanup.");
        }
    } catch (error) {
        // Don't fail the workflow if cleanup fails, just log it
        core.warning(`Failed to stop ROC process: ${error.message}`);
    }
}

cleanup();
