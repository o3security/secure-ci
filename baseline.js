// baseline.js — Automated baseline management for ROC Agent
//
// Storage strategy (API-first, cache fallback):
//   1. If api_key is set → load/save via backend API (persistent across machines/branches)
//   2. Otherwise → GitHub Actions Cache (free, no account needed)
//
// The backend API stores baselines per {org, repo, job, branch} in MongoDB.
// GitHub Cache key: roc-baseline-{GITHUB_JOB}-{GITHUB_REF_NAME}

const core = require("@actions/core");
const cache = require("@actions/cache");
const fs = require("fs-extra");
const axios = require("axios");

const BASELINE_PATH = "/tmp/roc-baseline.json";
const EGRESS_LOG_PATH = "/tmp/roc-egress-log.jsonl";

// ─── Cache key helpers ────────────────────────────────────────────────────────

function baselineCacheKey() {
    const job = process.env.GITHUB_JOB || "default";
    const ref = (process.env.GITHUB_REF_NAME || process.env.GITHUB_REF || "main")
        .replace(/[^a-zA-Z0-9_-]/g, "-");
    return `roc-baseline-${job}-${ref}`;
}

// ─── Backend API (persistent, cross-machine) ──────────────────────────────────

/**
 * Loads the baseline from the O3 Security backend API.
 * Returns null if no baseline exists yet or on error.
 */
async function loadBaselineFromAPI(apiKey, serverUrl) {
    const repo = process.env.GITHUB_REPOSITORY || "";
    const job = process.env.GITHUB_JOB || "default";
    const branch = process.env.GITHUB_REF_NAME || process.env.GITHUB_REF || "main";
    const base = serverUrl || "https://app.o3security.io";

    try {
        const resp = await axios.get(`${base}/api/v1/roc/baseline`, {
            params: { repo, job, branch },
            headers: { Authorization: `apiKey ${apiKey}` },
            timeout: 8000,
        });
        if (resp.data?.found) {
            core.info(`[Baseline] Loaded from backend: run #${resp.data.runs}, ${resp.data.totalDestinations} known destinations`);
            return resp.data;
        }
        core.info("[Baseline] No backend baseline yet — this is the first run");
        return null;
    } catch (e) {
        core.warning(`[Baseline] Could not load from backend: ${e.message}`);
        return null;
    }
}

/**
 * Saves the updated baseline to the O3 Security backend API.
 */
async function saveBaselineToAPI(apiKey, serverUrl, data) {
    const repo = process.env.GITHUB_REPOSITORY || "";
    const job = process.env.GITHUB_JOB || "default";
    const branch = process.env.GITHUB_REF_NAME || process.env.GITHUB_REF || "main";
    const base = serverUrl || "https://app.o3security.io";

    try {
        await axios.post(`${base}/api/v1/roc/baseline/upload`, {
            repo, job, branch,
            runs: data.runs,
            baseline: data.baseline,
        }, {
            headers: { Authorization: `apiKey ${apiKey}`, "Content-Type": "application/json" },
            timeout: 10000,
        });
        core.info(`[Baseline] Saved to backend: run #${data.runs}, ${Object.keys(data.baseline).length} destinations`);
    } catch (e) {
        core.warning(`[Baseline] Could not save to backend: ${e.message}`);
    }
}

// ─── GitHub Actions Cache (fallback) ─────────────────────────────────────────

async function loadBaselineFromCache() {
    const key = baselineCacheKey();
    try {
        const hit = await cache.restoreCache([BASELINE_PATH], key);
        if (!hit) {
            core.info(`[Baseline] No cache baseline for key: ${key} (first run)`);
            return null;
        }
        const data = await fs.readJson(BASELINE_PATH);
        core.info(`[Baseline] Loaded from cache: run #${data.runs}, ${Object.keys(data.baseline).length} known destinations`);
        return data;
    } catch (e) {
        core.warning(`[Baseline] Could not load from cache: ${e.message}`);
        return null;
    }
}

async function saveBaselineToCache(data) {
    const key = baselineCacheKey();
    try {
        await fs.writeJson(BASELINE_PATH, data, { spaces: 2 });
        const saveKey = `${key}-${process.env.GITHUB_RUN_ID || Date.now()}`;
        await cache.saveCache([BASELINE_PATH], saveKey);
        core.info(`[Baseline] Saved to cache: ${saveKey}`);
    } catch (e) {
        core.warning(`[Baseline] Could not save to cache: ${e.message}`);
    }
}

// ─── Egress log reader ────────────────────────────────────────────────────────

/**
 * Reads /tmp/roc-egress-log.jsonl written by the dpi binary.
 * Returns { "domain:port": count }
 */
async function readEgressLog() {
    const connections = {};
    try {
        if (!(await fs.pathExists(EGRESS_LOG_PATH))) {
            core.info("[Baseline] No egress log found");
            return connections;
        }
        const content = await fs.readFile(EGRESS_LOG_PATH, "utf8");
        for (const line of content.split("\n")) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            try {
                const entry = JSON.parse(trimmed);
                const key = `${entry.domain || entry.ip || "unknown"}:${entry.port || "443"}`;
                connections[key] = (connections[key] || 0) + 1;
            } catch { /* malformed line */ }
        }
        core.info(`[Baseline] ${Object.keys(connections).length} unique egress destinations observed`);
    } catch (e) {
        core.warning(`[Baseline] Error reading egress log: ${e.message}`);
    }
    return connections;
}

// ─── Diff + merge logic ───────────────────────────────────────────────────────

/**
 * Compares current run connections against historical baseline.
 * Returns { newDestinations, knownDestinations, firstRun }
 */
function diffBaseline(currentConnections, baseline) {
    if (!baseline || !baseline.baseline) {
        return {
            newDestinations: [],
            knownDestinations: Object.keys(currentConnections),
            firstRun: true,
        };
    }
    const newDestinations = [];
    const knownDestinations = [];
    for (const dest of Object.keys(currentConnections)) {
        if (baseline.baseline[dest]) {
            knownDestinations.push(dest);
        } else {
            newDestinations.push(dest);
        }
    }
    return { newDestinations, knownDestinations, firstRun: false };
}

/**
 * Merges current connections into the baseline, incrementing run count.
 */
function mergeBaseline(existing, currentConnections) {
    const runs = (existing?.runs || 0) + 1;
    const merged = { ...(existing?.baseline || {}) };
    for (const [dest, count] of Object.entries(currentConnections)) {
        merged[dest] = (merged[dest] || 0) + count;
    }
    return {
        job: process.env.GITHUB_JOB || "default",
        branch: process.env.GITHUB_REF_NAME || "main",
        runs,
        updated_at: new Date().toISOString(),
        baseline: merged,
    };
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/**
 * Full baseline lifecycle: load → read egress log → diff → merge → save.
 * Uses backend API if apiKey is present; falls back to GitHub Actions Cache.
 *
 * @param {string} apiKey - O3 Security API key (optional)
 * @param {string} serverUrl - O3 backend URL (optional)
 * @returns {{ newDestinations, knownDestinations, firstRun, runs, totalKnown }}
 */
async function runBaselineAnalysis(apiKey, serverUrl) {
    const useBackend = !!(apiKey);

    const [existing, currentConnections] = await Promise.all([
        useBackend ? loadBaselineFromAPI(apiKey, serverUrl) : loadBaselineFromCache(),
        readEgressLog(),
    ]);

    const { newDestinations, knownDestinations, firstRun } = diffBaseline(currentConnections, existing);
    const updated = mergeBaseline(existing, currentConnections);

    // Save to backend AND cache if API key present; cache-only otherwise
    if (useBackend) {
        await saveBaselineToAPI(apiKey, serverUrl, updated);
        await saveBaselineToCache(updated); // also save to cache as local backup
    } else {
        await saveBaselineToCache(updated);
    }

    return {
        newDestinations,
        knownDestinations,
        firstRun,
        runs: updated.runs,
        totalKnown: Object.keys(updated.baseline).length,
        storedIn: useBackend ? "backend+cache" : "cache",
    };
}

module.exports = {
    runBaselineAnalysis,
    loadBaselineFromAPI,
    saveBaselineToAPI,
    loadBaselineFromCache,
    saveBaselineToCache,
    readEgressLog,
    diffBaseline,
    mergeBaseline,
};
