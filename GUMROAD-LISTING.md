# Gumroad Listing — API Security Audit Kit

## Product Name
API Security Audit Kit

## Price
$19 (or name-your-price, $9 minimum)

## Summary (short)
Find vulnerabilities in your REST API in 30 minutes. 22 security tests, zero dependencies, beautiful HTML reports.

## Description (long)

### Stop shipping insecure APIs.

Run one command. Get a full security audit of any REST API in under 30 minutes.

**22 tests across 5 categories:**
- Rate limiting — does your API actually enforce limits?
- Injection attacks — SQL, XSS, prompt injection, CRLF, path traversal
- Input validation — oversized payloads, binary content, malformed JSON
- Auth boundaries — missing auth, invalid tokens, privilege escalation
- Error handling — info leakage, stack traces, inconsistent errors

**What you get:**
- The audit script (Node.js, zero dependencies, runs anywhere)
- HTML report generator — beautiful dark-theme reports you can share with your team
- JSON output for CI/CD integration
- Works with any REST API — just point it at your base URL

**How to use:**
```
node index.js https://your-api.com --auth "Bearer YOUR_TOKEN"
node index.js https://your-api.com --json | node report.js > report.html
```

**Built from real experience.** This kit was extracted from a 62-test security audit of a production agent mesh API that found 14 real vulnerabilities. It's not theoretical — it's battle-tested.

**Who it's for:**
- Developers shipping APIs who want a quick security sanity check before production
- DevOps teams adding security gates to CI/CD pipelines
- Freelancers who need to audit client APIs
- Anyone who's ever wondered "is my API actually secure?"

## Tags
api, security, audit, testing, developer-tools, devops, pentesting

## Thumbnail text
"22 Security Tests. Zero Dependencies. Beautiful Reports."
