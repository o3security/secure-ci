/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 250:
/***/ ((module) => {

"use strict";
module.exports = require("dns");

/***/ }),

/***/ 896:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 611:
/***/ ((module) => {

"use strict";
module.exports = require("http");

/***/ }),

/***/ 692:
/***/ ((module) => {

"use strict";
module.exports = require("https");

/***/ }),

/***/ 278:
/***/ ((module) => {

"use strict";
module.exports = require("net");

/***/ }),

/***/ 928:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ }),

/***/ 756:
/***/ ((module) => {

"use strict";
module.exports = require("tls");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// egress-interceptor.js — Pure-Node egress logger (eBPF fallback)
// Runs as a child process spawned from index.js when the DPI container
// fails to start or eBPF probes are unavailable (e.g., GitHub-hosted runners).
//
// Technique: Monkey-patch Node's net.Socket.connect + dns.lookup + https.request
// to capture every outbound connection the runner makes and write to the JSONL log.
// Works without any kernel features — just userspace Node.js.

const fs = __nccwpck_require__(896);
const net = __nccwpck_require__(278);
const dns = __nccwpck_require__(250);
const tls = __nccwpck_require__(756);
const https = __nccwpck_require__(692);
const http = __nccwpck_require__(611);
const path = __nccwpck_require__(928);

const LOG_PATH = process.argv[2] || '/tmp/roc-egress-log.jsonl';

// Ensure log file exists
try { fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true }); } catch (_) { }
try { if (!fs.existsSync(LOG_PATH)) fs.writeFileSync(LOG_PATH, ''); } catch (_) { }


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

process.stderr.write('[roc-interceptor] Node.js egress interceptor running\n');


// Keep alive
setInterval(() => { }, 60000);

module.exports = __webpack_exports__;
/******/ })()
;