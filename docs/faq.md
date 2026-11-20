# FAQ and troubleshooting

### `could not reach …: certificate verification failed`
You will not see this as a fatal error any more: when a certificate is not
trusted, SafeScope reports `tls.certificate.untrusted` and still runs the other
checks. If it still appears, the TLS handshake itself failed (see the next
answer).

### `TLS error: … wrong version number`
You pointed `https://` at a port that speaks plain HTTP (common with local dev
servers). Use `http://host:port/`.

### `could not resolve …`
The host name does not exist in DNS, or you are offline. Check the spelling;
`safescope scan example.com` adds `https://` for you.

### `timed out after 10s` / `scan time budget … exceeded`
The site is slow or drops connections. Raise `--timeout` (per request) or
`--max-time` (whole scan). The public web app uses 6 s per request and 25 s per
scan and cannot be changed.

### `429 too many scans` on the website
The public instance allows 10 scans per minute per IP. Wait a minute, or run
SafeScope locally (`pip install …` then `safescope scan`), which has no limit.

### `403 target not allowed` on the website
The public instance refuses targets that resolve to private or local addresses
and ports other than 80/443/8080/8443. Run the CLI on your own network for
those (that is allowed and expected).

### `only http:// and https:// targets are supported` / `not a valid host name`
SafeScope scans web sites. Use a URL like `https://example.com/path` or a plain
host name. URLs containing a user name or password are refused so credentials
never end up in reports.

### A check says `skipped`
The test could not run, so SafeScope does not claim a result either way. The
most common case is `tls.protocol.legacy_untested`: the local OpenSSL refuses
to offer TLS 1.0/1.1, so their support could not be probed.

### Is a grade of A+ proof that my site is secure?
No. It means the passive checks passed. See
[security-model.md](security-model.md#what-safescope-does-not-promise).

### How do I scan many sites?
`safescope scan a.com b.com --targets-file sites.txt --concurrency 4 -f json -o all.json`,
then `safescope report all.json -f markdown` for a readable summary.

### How do I show results in GitHub code scanning?
Generate SARIF and upload it with GitHub's official action:

```yaml
permissions:
  security-events: write
steps:
  - run: pip install safescope-scanner
  - run: safescope scan https://staging.example.com -f sarif -o safescope.sarif
  - uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: safescope.sarif
```

SafeScope findings are about a URL, not a source file, so the alert location is
the scanned URL.

### PowerShell refuses `.venv\Scripts\activate`
Run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
