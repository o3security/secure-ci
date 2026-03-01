// egress-interceptor.js — Pure-Node egress logger (eBPF fallback)
// Runs as a child process spawned from index.js when the DPI container
// fails to start or eBPF probes are unavailable (e.g., GitHub-hosted runners).
//
// Technique: Monkey-patch Node's net.Socket.connect + dns.lookup + https.request
// to capture every outbound connection the runner makes and write to the JSONL log.
// Works without any kernel features — just userspace Node.js.

const fs = require('fs');
const net = require('net');
const dns = require('dns');
const tls = require('tls');
const https = require('https');
const http = require('http');
const path = require('path');

const LOG_PATH = process.argv[2] || '/tmp/roc-egress-log.jsonl';
const FIM_LOG_PATH = process.argv[3] || '/tmp/roc-fim-events.jsonl';
const WORKSPACE = process.argv[4] || process.env.GITHUB_WORKSPACE || '';

// Ensure log file exists
try { fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true }); } catch (_) { }
try { if (!fs.existsSync(LOG_PATH)) fs.writeFileSync(LOG_PATH, ''); } catch (_) { }
try { if (!fs.existsSync(FIM_LOG_PATH)) fs.writeFileSync(FIM_LOG_PATH, ''); } catch (_) { }

const seen = new Set();

function appendEvent(obj) {
    try {
        fs.appendFileSync(LOG_PATH, JSON.stringify(obj) + '\n');
    } catch (_) { }
}

function logEgress(host, port, protocol, requestInfo) {
    const key = `${host}:${port}`;
    if (seen.has(key)) return;
    seen.add(key);

    const isIP = net.isIP(host) !== 0;
    const req = requestInfo || {};
    const event = {
        timestamp: new Date().toISOString(),
        domain: isIP ? '' : host,
        ip: isIP ? host : '',
        port: parseInt(port, 10) || 443,
        protocol: protocol || (port === 443 || port === '443' ? 'TLS' : 'TCP'),
        source: 'node-interceptor',
        step_name: process.env.GITHUB_ACTION || '',
        job: process.env.GITHUB_JOB || '',
        run_id: process.env.GITHUB_RUN_ID || '',
        // Full request details
        request: {
            method: req.method || null,
            uri: req.path || null,
            host: host,
            url: req.fullUrl || null,
            headers: req.headers || null,
        },
        // Process info from current Node process (best-effort)
        comm: process.title || 'node',
        cmdline: process.argv.slice(1).join(' ') || null,
        parent_comm: null,
    };
    appendEvent(event);
    process.stderr.write(`[roc-interceptor] ${req.method || 'TCP'} ${req.fullUrl || key}\n`);
}

// ── Patch net.Socket.connect ─────────────────────────────────────────────────
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function patchedConnect(...args) {
    try {
        const opts = typeof args[0] === 'object' ? args[0] : { host: args[1], port: args[0] };
        const host = opts.host || 'localhost';
        const port = opts.port || 80;
        // Skip loopback + private
        if (host !== 'localhost' && !host.startsWith('127.') && !host.startsWith('10.') &&
            !host.startsWith('192.168.') && host !== '::1') {
            logEgress(host, port, port === 443 ? 'TLS' : 'TCP');
        }
    } catch (_) { }
    return origConnect.apply(this, args);
};

// ── Patch https.request ──────────────────────────────────────────────────────
const origHttpsRequest = https.request;
https.request = function patchedHttpsRequest(url, options, callback) {
    try {
        let host, port, method, path, headers;
        if (typeof url === 'string') {
            const u = new URL(url);
            host = u.hostname;
            port = u.port || '443';
            path = u.pathname + u.search;
            method = (options && options.method) || 'GET';
            headers = (options && options.headers) || {};
        } else if (url && typeof url === 'object' && url.hostname) {
            host = url.hostname;
            port = url.port || '443';
            path = url.path || url.pathname || '/';
            method = url.method || (options && options.method) || 'GET';
            headers = url.headers || (options && options.headers) || {};
        } else if (options && options.hostname) {
            host = options.hostname;
            port = options.port || '443';
            path = options.path || '/';
            method = options.method || 'GET';
            headers = options.headers || {};
        }
        if (host) {
            const fullUrl = `https://${host}${path || ''}`;
            logEgress(host, port, 'HTTPS', { method, path, fullUrl, headers });
        }
    } catch (_) { }
    return origHttpsRequest.apply(this, arguments);
};

// ── Patch http.request ───────────────────────────────────────────────────────
const origHttpRequest = http.request;
http.request = function patchedHttpRequest(url, options, callback) {
    try {
        let host, port, method, path, headers;
        if (typeof url === 'string') {
            const u = new URL(url);
            host = u.hostname;
            port = u.port || '80';
            path = u.pathname + u.search;
            method = (options && options.method) || 'GET';
            headers = (options && options.headers) || {};
        } else if (url && url.hostname) {
            host = url.hostname;
            port = url.port || '80';
            path = url.path || url.pathname || '/';
            method = url.method || (options && options.method) || 'GET';
            headers = url.headers || (options && options.headers) || {};
        }
        if (host) {
            const fullUrl = `http://${host}${path || ''}`;
            logEgress(host, port, 'HTTP', { method, path, fullUrl, headers });
        }
    } catch (_) { }
    return origHttpRequest.apply(this, arguments);
};

// ── FIM watcher (if workspace provided) ─────────────────────────────────────
if (WORKSPACE && fs.existsSync(WORKSPACE)) {
    try {
        const chokidar = require('chokidar');
        chokidar.watch(WORKSPACE, {
            ignoreInitial: true,
            ignored: [
                /node_modules/,
                /\.git/,
                /\.(log|tmp)$/,
            ],
            persistent: true,
            depth: 5,
        }).on('change', (filePath) => {
            const event = {
                timestamp: new Date().toISOString(),
                path: filePath,
                action: 'MODIFIED',
                step_name: process.env.GITHUB_ACTION || '',
                job: process.env.GITHUB_JOB || '',
                source: 'node-interceptor',
            };
            try { fs.appendFileSync(FIM_LOG_PATH, JSON.stringify(event) + '\n'); } catch (_) { }
        }).on('add', (filePath) => {
            const event = {
                timestamp: new Date().toISOString(),
                path: filePath,
                action: 'CREATED',
                step_name: process.env.GITHUB_ACTION || '',
                job: process.env.GITHUB_JOB || '',
                source: 'node-interceptor',
            };
            try { fs.appendFileSync(FIM_LOG_PATH, JSON.stringify(event) + '\n'); } catch (_) { }
        });
        process.stderr.write(`[roc-interceptor] FIM watching: ${WORKSPACE}\n`);
    } catch (_) {
        // chokidar unavailable — skip FIM
        process.stderr.write('[roc-interceptor] chokidar not available, FIM disabled\n');
    }
}

process.stderr.write('[roc-interceptor] Node.js egress interceptor running\n');

// Keep alive
setInterval(() => { }, 60000);
