# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (latest) | Yes |

## Reporting a Vulnerability

**Do not open a public issue.** Instead, email the maintainer directly:

- **Email:** security@projectnavi.ai
- **Subject prefix:** `[navi-sanitize] SECURITY:`

Include:

- A description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The impact as you understand it

## Response Timeline

- **Acknowledge:** within 48 hours
- **Fix or disclose:** within 90 days

If the vulnerability is accepted, a fix will be released and credited in the changelog (unless you prefer to remain anonymous). If declined, you'll receive an explanation.

## Scope

This policy covers the navi-sanitize library itself — the pipeline stages, built-in escapers, and `walk()`. User-supplied escapers and downstream application logic are out of scope.
