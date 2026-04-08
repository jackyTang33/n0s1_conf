# Confluence Secret Scanner

A standalone, easy-to-read Confluence secret scanner. Scans page titles, bodies, and comments for leaked credentials using configurable regex rules.

## Features

- **CQL scope validation** — bad queries fail fast with clear error messages (no silent fallback to full-instance scan)
- **Pre-scan summary & approval** — see how many pages/spaces/comments will be scanned before committing
- **Parallel regex scanning** — `ProcessPoolExecutor` for true CPU parallelism (`--workers`)
- **Configurable regex rules** — edit `regex_patterns.yaml` to add/remove patterns
- **JSON report output** — findings saved to a structured JSON file

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure credentials

Copy `.env.example` to `.env` and fill in your Confluence details:

```bash
cp .env.example .env
```

```env
CONFLUENCE_SERVER=https://yourcompany.atlassian.net
CONFLUENCE_EMAIL=you@example.com
CONFLUENCE_TOKEN=your-api-token-here
```

Or pass them via CLI flags (see below).

### 3. Run

```bash
# Scan everything (with interactive approval prompt):
python -m confluence_scanner.main

# Scan a specific space with CQL, auto-approve:
python -m confluence_scanner.main --scope "cql:space=SEC AND type=page" --yes

# Use 4 parallel workers:
python -m confluence_scanner.main --scope "cql:space=DEV" --yes --workers 4

# Skip comment scanning:
python -m confluence_scanner.main --skip-comments --yes
```

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--server` | Confluence base URL | env `CONFLUENCE_SERVER` |
| `--email` | User email | env `CONFLUENCE_EMAIL` |
| `--api-key` | API token | env `CONFLUENCE_TOKEN` |
| `--scope` | CQL scope query (e.g. `"cql:space=SEC AND type=page"`) | None (all spaces) |
| `--regex-file` | Path to YAML regex rules | `regex_patterns.yaml` |
| `--report-file` | Output JSON report path | `confluence_report.json` |
| `-y`, `--yes` | Auto-approve scan summary (for CI/automation) | Off |
| `--workers` | Parallel workers: a number, or `auto` for `min(cpu_count, 8)` | `1` |
| `--skip-comments` | Don't scan page comments | Off |
| `--show-secrets` | Show raw matched secrets in logs (CAUTION!) | Off |
| `--post-comment` | Post warning comments on pages with leaks | Off |
| `--timeout` | HTTP request timeout (seconds) | None |
| `--limit` | Max pages per HTTP request | None |
| `--insecure` | Skip SSL verification | Off |
| `--debug` | Verbose debug logging | Off |

## Project Structure

```
confluence_scanner/
├── __init__.py              # Package marker
├── main.py                  # CLI entry-point & orchestration
├── confluence_controller.py # Confluence API client (connect, CQL, fetch pages)
├── scanner.py               # Regex engine, two-pass scan, parallel dispatch
├── regex_patterns.yaml      # Editable regex rules (YAML)
└── tests/
    ├── __init__.py
    └── test_scanner.py      # Unit tests
```

**No inheritance chains, no factory pattern, no platform abstraction.**
Each file is self-contained and does one thing.

## Regex Rules

Edit `confluence_scanner/regex_patterns.yaml` to customise detection rules:

```yaml
rules:
  - id: my_custom_rule
    description: My Custom API Key
    regex: '\bMYKEY_[a-zA-Z0-9]{32}\b'
    tags: [custom]
    keywords: [MYKEY_]
```

## Parallelisation Guide

| Scan size | Recommended `--workers` |
|-----------|------------------------|
| < 1,000 pages | `1` (default — fast enough) |
| 1,000–10,000 pages | `4` |
| > 10,000 pages | `auto` or your CPU core count |

Workers use `ProcessPoolExecutor` (not threads) for true CPU parallelism around Python's GIL.

## Running Tests

```bash
python -m pytest confluence_scanner/tests/ -v
```

## License

See [LICENSE](LICENSE).
