// baseline.js — ROC Agent baseline analysis + severity classification
//
// Runs in post.js at job-end. Reads egress JSONL and FIM JSONL produced by
// the dpi container, classifies each observation with severity, then sends
// the full enriched payload to POST /api/v1/roc/ingest.
//
// Phase 3 heuristics (ZERO external APIs):
//   - Known-registry list (50+ entries) → info
//   - Raw IP (net.isIP) → critical
//   - Private/RFC1918 IP → high
//   - TLS cert NotBefore < 14 days → high (extracted from egress JSONL)
//   - DNS TTL < 60s → high (dns.resolve from runner)
//   - FIM source file during install step → high

const core = require('@actions/core');
const fs = require('fs-extra');
const dns = require('dns').promises;
const net = require('net');
const { default: axios } = require('axios');
const path = require('path');

const EGRESS_LOG_PATH = '/tmp/roc-egress-log.jsonl';
const FIM_LOG_PATH = '/tmp/roc-fim-events.jsonl';
const BASELINE_CACHE_PATH = '/tmp/roc-baseline-cache.json';

// ─── Known-safe registries + CDNs (auto-downgrade to "info") ──────────────────

const KNOWN_REGISTRIES = new Set([
    // Package registries
    'registry.npmjs.org', 'registry.yarnpkg.com',
    'pypi.org', 'files.pythonhosted.org',
    'crates.io', 'static.crates.io',
    'pkg.go.dev', 'sum.golang.org', 'proxy.golang.org', 'storage.googleapis.com',
    'repo1.maven.org', 'central.maven.org', 'plugins.gradle.org',
    'nuget.org', 'api.nuget.org',
    'rubygems.org', 'index.rubygems.org',
    'packagist.org',
    'deb.debian.org', 'security.debian.org', 'archive.ubuntu.com',
    // GitHub & CDNs
    'github.com', 'api.github.com', 'raw.githubusercontent.com',
    'objects.githubusercontent.com', 'codeload.github.com',
    'uploads.github.com', 'ghcr.io',
    // Docker
    'registry-1.docker.io', 'auth.docker.io', 'registry.docker.io',
    'production.cloudflare.docker.com', 'index.docker.io',
    // CDNs
    'cloudflare.com', 'unpkg.com', 'cdn.jsdelivr.net',
    'fastly.net', 'akamaized.net', 'akamai.net', 'edgekey.net',
    'amazonaws.com', 's3.amazonaws.com',
    // CI infrastructure
    'actions-results-receiver-production.githubapp.com',
    'pipelines.actions.githubusercontent.com',
    'results-receiver.actions.githubusercontent.com',
    'api.snapcraft.io',
]);

// Domain suffix check (e.g. foo.pypi.org)
const KNOWN_SUFFIXES = [
    '.npmjs.org', '.npmjs.com', '.yarnpkg.com',
    '.pypi.org', '.pythonhosted.org',
    '.crates.io', '.golang.org', '.googleapis.com',
    '.maven.org', '.gradle.org', '.nuget.org',
    '.rubygems.org', '.packagist.org',
    '.debian.org', '.ubuntu.com',
    '.github.com', '.githubusercontent.com', '.ghcr.io',
    '.docker.io', '.docker.com',
    '.cloudflare.com', '.unpkg.com', '.jsdelivr.net',
    '.fastly.net', '.akamaized.net', '.akamai.net',
    '.amazonaws.com', '.s3.amazonaws.com',
    '.actions.githubusercontent.com', '.githubapp.com',
];

function isKnownRegistry(domain) {
    if (!domain) return false;
    if (KNOWN_REGISTRIES.has(domain)) return true;
    return KNOWN_SUFFIXES.some(s => domain.endsWith(s));
}

// ─── IP classification ────────────────────────────────────────────────────────

function isRawIP(str) {
    return net.isIP(str) !== 0;
}

function isPrivateIP(ip) {
    if (!ip || net.isIP(ip) === 0) return false;
    return (
        ip.startsWith('10.') ||
        ip.startsWith('127.') ||
        ip.startsWith('169.254.') ||
        ip.startsWith('::1') ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
        ip.startsWith('192.168.')
    );
}

// ─── DNS TTL check ────────────────────────────────────────────────────────────

async function getDNSTTL(domain) {
    try {
        // dns.resolve4 returns [{address, ttl}] with ttl option
        const records = await dns.resolve4(domain, { ttl: true });
        if (records && records.length > 0) return records[0].ttl;
    } catch { /* NXDOMAIN or timeout */ }
    return null;
}

// ─── TLS cert age check ───────────────────────────────────────────────────────

function certAgeDays(notBeforeIso) {
    if (!notBeforeIso) return null;
    try {
        const d = new Date(notBeforeIso);
        return Math.floor((Date.now() - d.getTime()) / 86_400_000);
    } catch { return null; }
}

// ─── Egress severity classifier ───────────────────────────────────────────────

async function classifyEgress(entry) {
    const domain = (entry.domain || entry.host || '').toLowerCase().replace(/\.$/, '');
    const ip = entry.ip || '';

    // Raw IP → critical (unless private)
    if (!domain && ip) {
        if (isPrivateIP(ip)) return { severity: 'high', severity_reason: 'private_ip' };
        return { severity: 'critical', severity_reason: 'raw_ip' };
    }
    if (domain && isRawIP(domain)) {
        if (isPrivateIP(domain)) return { severity: 'high', severity_reason: 'private_ip' };
        return { severity: 'critical', severity_reason: 'raw_ip' };
    }

    // Known registry → info
    if (domain && isKnownRegistry(domain)) {
        return { severity: 'info', severity_reason: 'known_registry' };
    }

    // TLS cert issued recently → high
    if (entry.tls_cert_not_before) {
        const ageDays = certAgeDays(entry.tls_cert_not_before);
        if (ageDays !== null && ageDays < 14) {
            return { severity: 'high', severity_reason: 'new_tls_cert', cert_age_days: ageDays };
        }
    }

    // DNS TTL very low → suspicious (likely fast-flux or newly spun up)
    if (domain) {
        const ttl = await getDNSTTL(domain);
        if (ttl !== null && ttl < 60) {
            return { severity: 'high', severity_reason: 'low_dns_ttl', dns_ttl: ttl };
        }
    }

    // Default: unknown public domain
    return { severity: 'medium', severity_reason: 'unknown_domain' };
}

// ─── FIM severity classifier ──────────────────────────────────────────────────

function classifyFIM(event) {
    const path = (event.path || '').toLowerCase();
    const step = (event.step_name || '').toLowerCase();
    const action = (event.action || '').toUpperCase();

    const isInstallStep = /npm install|pip install|yarn install|go mod|bundle install|apt-get|apt install/i.test(step);
    const isSourceFile = /\.(js|ts|jsx|tsx|py|go|java|rb|sh|bash)$/.test(path);
    const isLockFile = /\.(lock|sum)$|package-lock\.json|yarn\.lock|pipfile\.lock/i.test(path);
    const isConfigFile = /\.(yaml|yml|toml|json)$/.test(path);
    const isBuildArtifact = /^\/(dist|build|target|__pycache__|\.venv)\//.test('/' + path.split('/').slice(1).join('/'));

    if (isBuildArtifact) return { severity: 'low', severity_reason: 'build_artifact' };
    if (isSourceFile && isInstallStep) return { severity: 'high', severity_reason: 'source_during_install' };
    if (isSourceFile && action === 'MODIFIED') return { severity: 'high', severity_reason: 'source_modified' };
    if (isLockFile && isInstallStep) return { severity: 'medium', severity_reason: 'lockfile_during_install' };
    if (isLockFile) return { severity: 'medium', severity_reason: 'lockfile_modified' };
    if (isConfigFile && isInstallStep) return { severity: 'high', severity_reason: 'config_during_install' };
    return { severity: 'medium', severity_reason: 'file_modified' };
}

// ─── Log readers ──────────────────────────────────────────────────────────────

async function readJSONL(path) {
    try {
        if (!(await fs.pathExists(path))) return [];
        const content = await fs.readFile(path, 'utf8');
        const results = [];
        for (const line of content.split('\n')) {
            const t = line.trim();
            if (!t) continue;
            try { results.push(JSON.parse(t)); } catch { /* skip */ }
        }
        return results;
    } catch { return []; }
}

// ─── File-based cache (replaces @actions/cache which can't be bundled by ncc)
// On GitHub-hosted runners, RUNNER_TOOL_CACHE is /opt/hostedtoolcache — not
// persisted across runs. On self-hosted runners it IS persistent.
// For GitHub-hosted: the backend (api_key path) is the primary persistence;
// cache-only mode gives a single-run view (no cross-run baseline without api_key).

function cacheFilePath() {
    const job = (process.env.GITHUB_JOB || 'default').replace(/[^a-zA-Z0-9._-]/g, '-');
    const ref = (process.env.GITHUB_REF_NAME || 'main').replace(/[^a-zA-Z0-9._-]/g, '-');
    const repo = (process.env.GITHUB_REPOSITORY || 'unknown').replace(/[^a-zA-Z0-9._-]/g, '-');
    // Prefer a persistent directory; fall back to /tmp (ephemeral but safe)
    const base = process.env.RUNNER_TOOL_CACHE || '/tmp';
    return path.join(base, `roc-baseline-${repo}-${job}-${ref}.json`);
}

async function loadFromCache() {
    try {
        const fp = cacheFilePath();
        if (await fs.pathExists(fp)) return await fs.readJson(fp);
    } catch { /* ignore */ }
    return null;
}

async function saveToCache(data) {
    try {
        await fs.outputJson(cacheFilePath(), data, { spaces: 2 });
    } catch (e) { core.warning(`[Baseline] Cache save failed: ${e.message}`); }
}

// ─── Simple cache-only baseline (no api_key) ─────────────────────────────────

async function runCacheOnlyBaseline(egressRaw) {
    const existing = await loadFromCache();
    const currentKeys = Object.fromEntries(
        egressRaw.map(e => [`${e.domain || e.ip || 'unknown'}:${e.port || 443}`, 1])
    );

    const newDestinations = [];
    const baseline = existing?.baseline || {};
    for (const key of Object.keys(currentKeys)) {
        if (!baseline[key]) newDestinations.push(key);
        baseline[key] = (baseline[key] || 0) + 1;
    }

    const runs = (existing?.runs || 0) + 1;
    const firstRun = !existing;
    await saveToCache({ runs, baseline, updated_at: new Date().toISOString() });

    return { firstRun, newDestinations, knownDestinations: Object.keys(baseline), runs, storedIn: 'cache' };
}

// ─── Main ingest (api_key present) ───────────────────────────────────────────

async function runIngest(apiKey, serverUrl) {
    // Strip /graphql suffix — server_url is the GraphQL endpoint but ingest is REST
    const base = (serverUrl || 'https://api.codexsecurity.io').replace(/\/graphql\/?$/, '');
    const repo = process.env.GITHUB_REPOSITORY || '';
    const job = process.env.GITHUB_JOB || 'default';
    const branch = process.env.GITHUB_REF_NAME || process.env.GITHUB_REF || 'main';
    const run_id = process.env.GITHUB_RUN_ID || String(Date.now());
    const run_number = process.env.GITHUB_RUN_NUMBER || null;
    const workflow = process.env.GITHUB_WORKFLOW || '';

    // Read raw logs
    const [egressRaw, fimRaw] = await Promise.all([
        readJSONL(EGRESS_LOG_PATH),
        readJSONL(FIM_LOG_PATH),
    ]);

    core.info(`[Baseline] ${egressRaw.length} egress connections, ${fimRaw.length} FIM events to process`);

    // Deduplicate by domain:port:comm — same endpoint from different processes
    // (e.g. npm + curl both hitting registry.npmjs.org) logs as separate supply-chain events.
    const seen = new Set();
    const egressDeduped = egressRaw.filter(e => {
        const domain = (e.domain || e.host || e.ip || 'unknown').toLowerCase();
        const port = e.port || 443;
        const comm = e.comm || '';
        const key = `${domain}:${port}:${comm}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
    core.info(`[Baseline] ${egressDeduped.length} unique egress destinations after dedup`);

    // Classify egress — run DNS checks in parallel (capped at 100)
    const egressToCheck = egressDeduped.slice(0, 100);
    const egressClassified = await Promise.all(
        egressToCheck.map(async (e) => {
            const domain = (e.domain || e.host || e.ip || 'unknown').toLowerCase();
            const port = e.port || 443;
            const comm = e.comm || '';
            // Key includes comm so UI can show "npm → registry.npmjs.org" separately from "curl → registry.npmjs.org"
            const key = comm ? `${domain}:${port}:${comm}` : `${domain}:${port}`;
            const { severity, severity_reason, ...extra } = await classifyEgress(e);
            return {
                key, severity, severity_reason,
                tls_cert_not_before: e.tls_cert_not_before || null,
                // Supply chain source fields — displayed in UI Captures tab + Step Summary
                comm,
                cmdline: e.cmdline || '',
                parent_comm: e.parent_comm || '',
                source: e.source || 'openssl',
                ...extra,
            };
        })
    );

    // Classify FIM
    const fimClassified = fimRaw.map(e => {
        const { severity, severity_reason } = classifyFIM(e);
        const key = `${e.path || 'unknown'}::${e.step_name || 'unknown'}`;
        return {
            key, severity, severity_reason,
            sha256: e.sha256 || null,
            before_sha256: e.before_sha256 || null,
        };
    });

    // Send to backend
    try {
        const resp = await axios.post(`${base}/api/v1/roc/ingest`, {
            repo, job, branch, run_id, run_number, workflow,
            egress: egressClassified,
            fim_events: fimClassified,
        }, {
            headers: { Authorization: `apiKey ${apiKey}`, 'Content-Type': 'application/json' },
            timeout: 20000,
        });

        const result = resp.data;
        core.info(`[Baseline] Ingested: phase=${result.phase}, run #${result.run_count}, ${result.deviations} deviation(s)`);

        const highCritical = result.high_severity_deviations || [];
        if (highCritical.length > 0) {
            core.warning(`[Baseline] ⚠️  ${highCritical.length} HIGH/CRITICAL deviation(s): ${highCritical.map(d => d.key).join(', ')}`);
        }

        // Also save to cache as local backup
        const cacheData = { runs: result.run_count, baseline: Object.fromEntries(egressClassified.map(e => [e.key, 1])), updated_at: new Date().toISOString() };
        await saveToCache(cacheData);

        return {
            phase: result.phase,
            deviations: result.deviations,
            high_severity_deviations: highCritical,
            newDestinations: highCritical.map(d => d.key || d),   // ← was missing, crashed post.js
            run_count: result.run_count,
            egressClassified,
            fimClassified,
            firstRun: result.run_count === 1,
            storedIn: 'backend+cache',
        };
    } catch (e) {
        core.warning(`[Baseline] Backend ingest failed (${e.message}), falling back to cache-only`);
        return runCacheOnlyBaseline(egressRaw);
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

async function runBaselineAnalysis(apiKey, serverUrl) {
    if (apiKey) {
        return runIngest(apiKey, serverUrl);
    }
    // Cache-only (no api_key)
    const egressRaw = await readJSONL(EGRESS_LOG_PATH);
    return runCacheOnlyBaseline(egressRaw);
}

module.exports = {
    runBaselineAnalysis,
    classifyEgress,
    classifyFIM,
    isKnownRegistry,
    isPrivateIP,
    isRawIP,
    readJSONL,
};
