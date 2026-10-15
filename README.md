# FeviconHashGenerator

Discovers website favicons and computes Shodan/FOFA-compatible MMH3 hashes, for asset discovery and infrastructure pivoting during authorized security testing.

- Concurrent scanning with a live dashboard (progress bar, results table, hash clusters, ready-made Shodan/FOFA queries)
- Finds icons via `<link rel=icon>`, `apple-touch-icon`, `data:` URIs, `<base href>`, and fallback paths (`/favicon.ico`, `/favicon.png`, `/apple-touch-icon.png`)
- Outputs TSV, CSV, or JSON (includes MD5 and SHA256)
- Restricted to `http`/`https`: page-controlled `file://`, `gopher://`, etc. are never fetched

## Requirements

- Python 3.7+
- `curl`
- Optional: `pip install mmh3` (faster hashing; a pure-Python fallback is built in)

## Install

```bash
chmod +x FeviconHashGenerator.py
```

## Usage

```bash
./FeviconHashGenerator.py [options] [targets ...]
```

Targets can be URLs or bare hostnames, passed as arguments, via `-i`, or via stdin.

## Commands

```bash
# Single target
./FeviconHashGenerator.py https://www.groupebpce.com

# Multiple targets
./FeviconHashGenerator.py www.groupebpce.com https://www.natixis.com

# From a file, saved as TSV (format inferred from extension)
./FeviconHashGenerator.py -i domains.txt -o results.tsv

# CSV / JSON output
./FeviconHashGenerator.py -i domains.txt -o results.csv
./FeviconHashGenerator.py -i domains.txt -o results.json
./FeviconHashGenerator.py -i domains.txt -f json -o results.out

# High concurrency, custom timeout
./FeviconHashGenerator.py -i domains.txt -t 50 --timeout 15

# Read targets from stdin
cat subs.txt | ./FeviconHashGenerator.py
./FeviconHashGenerator.py -i - < subs.txt

# Pipe machine-readable output (dashboard stays on stderr)
cat subs.txt | ./FeviconHashGenerator.py -f json 2>/dev/null | jq -r '.[] | select(.status=="OK") | .shodan_query'
cat subs.txt | ./FeviconHashGenerator.py 2>/dev/null | cut -f1,5

# Hash every discovered icon, not just the first hit
./FeviconHashGenerator.py -i domains.txt --all -o results.json

# Skip /favicon.ico etc. fallback probing
./FeviconHashGenerator.py -i domains.txt --no-fallback

# Ignore TLS errors, route through Burp
./FeviconHashGenerator.py target.com -k -x http://127.0.0.1:8080

# Custom headers / User-Agent
./FeviconHashGenerator.py target.com -H "X-Bug-Bounty: researcher" -H "Cookie: a=b"
./FeviconHashGenerator.py target.com --user-agent "Mozilla/5.0 ..."

# Retries on transient TLS/reset errors
./FeviconHashGenerator.py -i domains.txt -r 3

# Quiet / no color (logs, cron)
./FeviconHashGenerator.py -i domains.txt -q --no-color -o results.tsv
```

## Options

| Option | Description |
|---|---|
| `targets` | URLs or hostnames |
| `-i, --input FILE` | File with one target per line (`-` = stdin; `#` comments ignored) |
| `-o, --output FILE` | Write results to file (format from extension or `-f`) |
| `-f, --format` | `tsv` (default), `csv`, `json` |
| `-t, --threads N` | Concurrent targets (default 10) |
| `--timeout SEC` | Per-request timeout (default 20) |
| `-r, --retries N` | Retries on transient TLS/reset errors (default 1) |
| `-a, --all` | Hash every discovered icon |
| `--no-fallback` | Don't probe common favicon paths |
| `-k, --insecure` | Skip TLS verification |
| `-x, --proxy URL` | Proxy passed to `curl -x` |
| `-H, --header H` | Extra header (repeatable) |
| `--user-agent UA` | Override User-Agent |
| `-q, --quiet` | No dashboard output |
| `--no-color` | Disable ANSI colors |

## Output columns

`input_url`, `final_page_url`, `favicon_url`, `bytes`, `shodan_favicon_hash`, `content_type`, `status`, `md5`, `sha256`, `source`, `kind`, `error`

JSON adds `shodan_query` and `fofa_query`.

Statuses: `OK`, `NO_FAVICON`, `PAGE_ERROR`, `ERROR`, `SKIPPED`

## Search queries

```text
Shodan: http.favicon.hash:<hash>
FOFA:   icon_hash="<hash>"
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | At least one favicon hashed |
| `1` | No favicon hashed |
| `2` | Usage / I/O error (missing curl, unreadable input, unwritable output) |
| `130` | Interrupted (Ctrl-C); partial results are still written |

## Authorized use only

Use only against assets you own or are explicitly authorized to test (e.g., in-scope bug bounty programs).

## Owner

**Secure Startups LLC**
[www.SecureStartups.com](https://www.SecureStartups.com)
