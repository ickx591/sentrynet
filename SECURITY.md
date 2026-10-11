# Security policy

## Supported versions

Security fixes are applied to the latest Community Edition release. Operators
should upgrade promptly and keep Debian or Ubuntu security updates current.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Send a private
report to the repository maintainer using GitHub's private vulnerability
reporting feature. Include:

- The affected version and installation method.
- A concise description of the impact.
- Reproduction steps or a minimal proof of concept.
- Any suggested mitigation, if known.

Avoid including real credentials, session cookies, webhook URLs, private IP
inventory, access logs, or other production data. Reports will be acknowledged
as soon as practical and coordinated disclosure is appreciated.

## Deployment expectations

SentryNet is a privileged operations tool. Keep the dashboard on loopback or
behind a correctly configured HTTPS reverse proxy, restrict access to trusted
operators, enable MFA, and protect `/opt/sentrynet/.env.postgres` and
`.admin.json` as root-only files.
