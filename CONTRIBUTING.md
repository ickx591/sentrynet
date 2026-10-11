# Contributing

Contributions that improve reliability, portability, security, accessibility,
or operator experience are welcome.

## Development setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r app/requirements.txt
cd app
../.venv/bin/python -m unittest discover -s tests -v
```

Run syntax checks before submitting a change:

```bash
bash -n install.sh uninstall.sh
python3 -m compileall -q app
```

## Pull requests

- Keep changes focused and explain their operator-facing impact.
- Add or update tests for security, parsing, retention, and database behavior.
- Never commit runtime state, real logs, credentials, database URLs, webhook
  URLs, private keys, or generated admin accounts.
- Preserve Debian/Ubuntu, nginx/Apache, and upgrade compatibility unless the
  change explicitly documents a migration.
- Treat automated blocking changes cautiously: false positives can interrupt
  legitimate traffic.

Security reports should follow `SECURITY.md` rather than the public issue
tracker.
