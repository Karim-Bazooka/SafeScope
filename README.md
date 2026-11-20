<div align="center">

# 🛡️ SafeScope

**A safe, non-intrusive web security posture scanner.**

Check HTTPS, TLS certificates, security headers, cookies and information leaks in seconds —
from your terminal, your CI pipeline, a web page or Python code. Zero dependencies.

[![PyPI](https://img.shields.io/pypi/v/safescope-scanner)](https://pypi.org/project/safescope-scanner/)
[![CI](https://github.com/Karim-Bazooka/SafeScope/actions/workflows/ci.yml/badge.svg)](https://github.com/Karim-Bazooka/SafeScope/actions/workflows/ci.yml)
[![Real-world scans](https://github.com/Karim-Bazooka/SafeScope/actions/workflows/real-world.yml/badge.svg)](https://github.com/Karim-Bazooka/SafeScope/actions/workflows/real-world.yml)
![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**🌐 Try it live: [safescope-one.vercel.app](https://safescope-one.vercel.app)**

[Quick start](#-quick-start) · [Usage](#-usage) · [Checks](#-what-it-checks) · [Web app](#-web-app) · [CI](#%EF%B8%8F-use-it-in-ci) · [Limits](#%EF%B8%8F-what-safescope-is-not) · [Docs](#-documentation) · [العربية](docs/README.ar.md)

<img src="docs/images/html-report.png" alt="SafeScope HTML report" width="720">

</div>

---

## Why SafeScope?

Most small teams and solo developers ship websites without checking the basics: is HTTP
redirected? Is HSTS on? Are session cookies `HttpOnly`? Is the server leaking `PHP/7.4.3`?

SafeScope answers those questions with **passive checks only**: a handful of normal `GET`
requests and TLS handshakes, exactly like a browser. No fuzzing, no payloads, no exploitation —
safe to run against production and easy to put in CI.

- **Actionable** — every finding says why it matters and how to fix it, with references.
- **Honest** — a test that could not run is reported as `skipped`, never as a pass; heuristic
  findings say `confidence: medium`.
- **Graded** — a 0–100 score and an A+ → F grade ([how it's computed](docs/scoring.md)).
- **Five output formats** — console, JSON, Markdown, self-contained HTML and SARIF.
- **Many sites at once** — scan a list of targets in parallel.
- **CI-ready** — `--fail-on medium` exit codes and a ready-made GitHub Action.
- **Web app included** — hardened against SSRF and DNS rebinding; deploy your own on Vercel.
- **Zero dependencies** — pure Python standard library.

## 🚀 Quick start

Requires Python 3.10 or newer.

**Linux / macOS**

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install safescope-scanner
safescope scan example.com
```

**Windows (PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install safescope-scanner
safescope scan example.com
```

Try every finding safely against the bundled, deliberately misconfigured demo server:

```bash
git clone https://github.com/Karim-Bazooka/SafeScope.git && cd SafeScope
python examples/vulnerable_demo_server.py &          # http://127.0.0.1:8000
safescope scan http://127.0.0.1:8000 --skip tls
```

```text
SafeScope v0.2.1
Target : http://127.0.0.1:8000/
Grade  :  F   score 5/100  (0.0s)

TRANSPORT
  FAIL HTTPS is not available [high]
       ↳ Serve the site over HTTPS (free certificates are available from
         Let's Encrypt).
HEADERS
  WARN CSP allows unsafe script sources [medium]
       · default-src * 'unsafe-inline' 'unsafe-eval'
  ...
Issues : 0 critical  1 high  6 medium  5 low  1 info
```

## 🧰 Usage

```bash
safescope scan example.com                                  # coloured console report
safescope scan example.com -f html -o report.html           # shareable HTML report
safescope scan example.com -f json -o scan.json             # machine readable
safescope scan example.com -f sarif -o safescope.sarif      # SARIF 2.1.0 (code scanning)
safescope scan a.com b.com --targets-file sites.txt         # several sites, 4 in parallel
safescope scan example.com --only headers,cookies           # run a subset of checks
safescope scan staging.example.com --fail-on medium         # exit 1 on medium+ findings
safescope scan example.com --max-time 20 --timeout 5        # time limits
safescope scan example.com --public-only                    # refuse private/internal targets
safescope report scan.json -f html -o report.html           # re-render a saved scan
safescope checks                                            # list the checks
safescope serve                                             # web UI on http://127.0.0.1:8000
```

| Exit code | Meaning |
|---|---|
| `0` | Scan finished, nothing at or above `--fail-on` |
| `1` | Findings at or above `--fail-on` |
| `2` | Usage error (bad URL, unknown check, bad report file…) |
| `3` | A target was unreachable (the others are still reported) |

From Python:

```python
from safescope import scan

result = scan("example.com")
print(result.grade, result.score)
for finding in result.problems:
    print(finding.severity.label, finding.id, finding.recommendation)
```

## 🔍 What it checks

| Check | ID | Looks at |
|---|---|---|
| HTTPS & HSTS | `transport` | HTTPS availability, HTTP→HTTPS redirect, HTTPS→HTTP downgrade, HSTS presence, `max-age`, `includeSubDomains` |
| TLS & certificate | `tls` | Trusted chain and host name, expiry (warns at 30 days), negotiated protocol, TLS 1.0/1.1 still accepted, legacy-only servers |
| Security headers | `headers` | CSP (incl. `unsafe-inline`/`unsafe-eval`/wildcards), clickjacking protection, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, deprecated `X-XSS-Protection` |
| Cookie security | `cookies` | `Secure`, `HttpOnly` (session-like cookies), `SameSite`, `SameSite=None` without `Secure` |
| Information disclosure | `disclosure` | Version banners, CORS `*` with credentials, `/.well-known/security.txt` |

Every finding has a stable ID such as `headers.csp.missing`. The full list, with severities, is
in the [check catalogue](docs/checks.md).

## 🌐 Web app

A public instance runs at **<https://safescope-one.vercel.app>** (it scores A+ when it scans
itself). Run your own with `safescope serve`, or:

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2FKarim-Bazooka%2FSafeScope)

```text
GET /api/scan?target=example.com              → JSON result
GET /api/scan?target=example.com&format=html  → full HTML report
GET /api/health                               → {"status": "ok"}
```

Because it accepts URLs from anyone, the web service is hardened: SSRF guard with DNS pinning
on every connection and redirect, web ports only, 6 s per request and 25 s per scan, 4
concurrent scans per instance, 10 scans per minute per client, strict CSP and no CORS. Details
and limits: [security model](docs/security-model.md), [deployment](docs/deploy.md).

## ⚙️ Use it in CI

```yaml
# .github/workflows/security.yml
name: Security posture
on:
  schedule: [{ cron: "0 6 * * 1" }]   # every Monday
  workflow_dispatch:
jobs:
  safescope:
    runs-on: ubuntu-latest
    steps:
      - uses: Karim-Bazooka/SafeScope@v0.2.1
        with:
          target: https://staging.example.com
          fail-on: medium
```

The action writes a Markdown summary to the job page, exposes `grade` and `score` outputs and
uploads the HTML and JSON reports as an artifact. For GitHub code scanning, see the
[SARIF example](docs/faq.md#how-do-i-show-results-in-github-code-scanning).

## ⚠️ What SafeScope is not

- **Not proof of security.** A good grade means the passive checks passed — nothing more.
- **Not a penetration test.** SafeScope does not look for application vulnerabilities such as
  XSS, SQL injection or broken authentication, and never sends attack payloads.
- **Only for authorised targets.** Scan sites you own or have explicit permission to test
  ([acceptable use](docs/acceptable-use.md)).

## 📚 Documentation

| Document | What's inside |
|---|---|
| [Check catalogue](docs/checks.md) | Every finding ID, status, severity and meaning |
| [Architecture](docs/architecture.md) | How the modules fit together, lifecycle of a scan |
| [Security model](docs/security-model.md) | SSRF and DNS rebinding protection, service limits, what is not promised |
| [Scoring](docs/scoring.md) | How the score and grade are computed |
| [FAQ](docs/faq.md) | Common errors and how-tos |
| [Writing a check](docs/writing-checks.md) | Step-by-step guide for contributors |
| [Deployment](docs/deploy.md) | Vercel and self-hosting |
| [Acceptable use](docs/acceptable-use.md) | Rules for scanning |
| [Changelog](CHANGELOG.md) | What changed in each release |

## 🗺️ Roadmap

- [x] **v0.1** — five passive checks, four report formats, CLI, GitHub Action, web app
- [x] **v0.2** — DNS-rebinding-safe web service, honest `skipped` results, confidence levels,
  multi-target scanning, SARIF, saved-report re-rendering, stricter CI
- [ ] **v0.3** — config file (`safescope.toml`) to accept known findings, baseline diff between scans
- [ ] **v0.4** — more passive checks: mixed content, subresource integrity, DNS (CAA), email (SPF/DMARC)
- [ ] **v1.0** — stable IDs and JSON schema, tracked grades over time

Ideas and votes are welcome in [Issues](https://github.com/Karim-Bazooka/SafeScope/issues).

## 🤝 Contributing

New checks, bug reports and docs improvements are welcome. The codebase is small, fully typed
and has 150+ tests that run without internet. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and
issues labelled `good first issue`. To report a vulnerability in SafeScope itself, see
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Karim
