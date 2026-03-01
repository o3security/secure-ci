# ROC Agent — O3 Security

A GitHub Action that monitors your CI/CD workflow for runtime security threats using deep packet inspection (DPI) and eBPF.

**Decrypts SSL/TLS traffic** at the library level (no proxy, no cert changes) and detects secrets, credentials, and anomalous connections exfiltrated during your builds.

---

## Quick Start

### With O3 Security dashboard (full features)

```yaml
steps:
  - uses: o3security/roc-agent@v1
    with:
      api_key: ${{ secrets.O3_API_KEY }}
      project_name: my-app

  - name: Build
    run: npm install && npm run build
```

Rules, whitelists, and alert thresholds are managed in the O3 Security dashboard — policy is fetched at job start via your `api_key`.

### Open-source / no login required

```yaml
steps:
  - uses: o3security/roc-agent@v1
    with:
      policy: audit        # monitor only — no account needed
      print_only: "true"   # print events to the log

  - name: Build
    run: npm install && npm run build
```

---

## Inline Policy (open-source mode)

Configure security policy directly in your workflow — no O3 Security account required.  
Internally, the action converts these inputs to an inline YAML policy file and passes it to the DPI binary.

### Audit mode (default)

Monitor all outbound connections. Findings printed to the job log.

```yaml
- uses: o3security/roc-agent@v1
  with:
    policy: audit
    print_only: "true"
```

### Block mode

Drop TCP 80/443 connections to any destination not in `allowed_domains` / `allowed_ips` / `allowed_cidrs`.

> **SSH (port 22) is always allowed first — you cannot be locked out of the runner.**

```yaml
- uses: o3security/roc-agent@v1
  with:
    policy: block
    allowed_domains: |
      api.github.com:443
      *.githubusercontent.com
      registry.npmjs.org:443
      pypi.org:443
    allowed_ips: ""
    allowed_cidrs: |
      10.0.0.0/8
      192.168.0.0/16
```

### Block mode with secret detection patterns

Combine egress blocking with custom secret scanning:

```yaml
- uses: o3security/roc-agent@v1
  with:
    policy: block
    allowed_domains: |
      api.github.com:443
      registry.npmjs.org:443
    patterns: .github/roc-patterns.yaml
```

Where `.github/roc-patterns.yaml`:
```yaml
patterns:
  - id: aws_access_key
    regex: 'AKIA[0-9A-Z]{16}'
  - id: github_token
    regex: 'ghp_[A-Za-z0-9]{36}'
  - id: slack_webhook
    regex: 'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'
```

### Inline policy YAML format (passed to `--policy-file`)

The action auto-generates this from your action inputs, but you can also pass a file directly:

```yaml
# roc-policy.yaml
policy: block           # audit | block

whitelist:
  domains:
    - api.github.com:443
    - "*.githubusercontent.com"
    - registry.npmjs.org
  ips:
    - 1.1.1.1
  cidrs:
    - 10.0.0.0/8

patterns:               # optional: secret detection
  - id: aws_key
    regex: 'AKIA[0-9A-Z]{16}'
```

---

## Inputs

### O3 Security dashboard (optional)

| Input | Default | Description |
|-------|---------|-------------|
| `api_key` | _(empty)_ | API key from O3 Security (leave blank for open-source mode) |
| `server_url` | `https://api.codexsecurity.io/graphql` | O3 Security API URL |
| `project_name` | _(empty)_ | Project name in the dashboard |

### Inline policy (open-source mode)

| Input | Default | Description |
|-------|---------|-------------|
| `policy` | `audit` | `audit` — monitor only. `block` — drop TCP 80/443 not in allowlist |
| `allowed_domains` | _(empty)_ | Allowed domains when `policy=block`. One per line or CSV. Supports `host:port` |
| `allowed_ips` | _(empty)_ | Allowed IPs when `policy=block`. One per line or CSV |
| `allowed_cidrs` | _(empty)_ | Allowed CIDR ranges when `policy=block`. One per line or CSV |

### Detection

| Input | Description |
|-------|-------------|
| `patterns` | Path to a YAML file with custom regex patterns for secret scanning |

### SIEM Integration

| Input | Description |
|-------|-------------|
| `splunk_url` | Splunk HEC URL |
| `splunk_token` | Splunk HEC token |
| `es_url` | Elasticsearch cluster URL |
| `es_index` | Elasticsearch index |
| `es_user` | Elasticsearch username |
| `es_pass` | Elasticsearch password |

### Advanced

| Input | Default | Description |
|-------|---------|-------------|
| `print_only` | `false` | Print events to log only — skip upload to O3 backend |
| `debug` | `false` | Verbose debug logging |
| `docker_image` | `public.ecr.aws/f9o7b7m0/roc` | Override the ROC Docker image (air-gapped environments) |

---

## How block mode works

When `policy: block`, the DPI binary applies iptables rules to the runner:

```
O3SECURITY-EGRESS chain (jumps from OUTPUT):
  1. ACCEPT tcp dpt:22          ← SSH always allowed (no lockout)
  2. ACCEPT tcp spt:22          ← SSH replies
  3. ACCEPT on lo               ← Loopback
  4. ACCEPT ESTABLISHED,RELATED ← Don't break in-flight sessions
  5. ACCEPT dst=<allowlisted>   ← Your allowed_domains/ips/cidrs
  ...
  N. DROP tcp dpt:80            ← Block outbound HTTP
  N. DROP tcp dpt:443           ← Block outbound HTTPS
```

Rules are **removed on job completion** via a deferred cleanup — even on error paths or panics.

---

## Comparison vs Step Security Harden Runner

| Feature | ROC Agent | Step Security Harden Runner |
|---------|-----------|----------------------------|
| No account required | ✅ (`policy: audit/block`) | ❌ |
| Egress block mode | ✅ iptables | ✅ |
| TLS plaintext inspection | ✅ eBPF uprobe | ❌ |
| Secret detection in traffic | ✅ | ❌ |
| Per-step event correlation | ✅ | Limited |
| Custom patterns | ✅ YAML file | ❌ |
| SIEM integration | ✅ Splunk / Elasticsearch | ❌ |
| SSH lockout protection | ✅ Guaranteed | ✅ |
