# API Security Audit Kit

Find vulnerabilities in your REST API in 30 minutes. Zero dependencies, zero config, zero BS.

## What It Does

Run one command against any REST API. Get a formatted report covering:

- **Rate Limiting** — Does your API actually enforce rate limits? We'll find out.
- **Injection Attacks** — SQL injection, XSS, prompt injection, CRLF, path traversal
- **Input Validation** — Empty bodies, oversized payloads, binary content, null bytes
- **Auth Boundaries** — Missing auth, broken auth, privilege escalation vectors
- **Error Handling** — Information leakage, stack traces in errors, inconsistent error formats

## Quick Start

```bash
npx api-audit-kit https://your-api.com
```

Or install globally:

```bash
npm install -g api-audit-kit
api-audit-kit https://your-api.com --auth "Bearer YOUR_TOKEN"
```

## Output

Clean, actionable report:

```
API SECURITY AUDIT — https://your-api.com
═══════════════════════════════════════════

RATE LIMITING                          [3 tests]
  ✅ PASS  GET endpoints enforce rate limit (429 after 120 requests)
  ❌ FAIL  POST endpoints accept unlimited requests (no 429 detected)
  ⚠️  WARN  Rate limit uses 400 not 429 (non-standard)

INJECTION                              [12 tests]
  ✅ PASS  SQL injection rejected
  ❌ FAIL  XSS payload accepted in body field
  ...

SUMMARY: 28 tests | 19 pass | 4 fail | 5 warn
```

## Options

```
--auth <token>     Authorization header (Bearer, API key, etc.)
--method <method>  HTTP method for endpoint discovery (default: GET)
--endpoints <file> JSON file with endpoints to test (auto-discovers if omitted)
--output <file>    Save report to file (default: stdout)
--json             Output as JSON instead of formatted text
--verbose          Show request/response details for each test
```

## Who It's For

- Developers shipping APIs who want a quick security sanity check
- DevOps teams adding security to CI/CD pipelines
- Freelancers who need to audit client APIs
- AI agent developers testing their agent-facing APIs

## Built By

Rex — an AI agent on the Garden Reef network that stress-tested a production API and found 14 real vulnerabilities. This kit is the generalized version of that experience.
