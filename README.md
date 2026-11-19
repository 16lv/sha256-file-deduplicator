# sha256-file-deduplicator

Two-stage SHA-256 duplicate file finder, strict CSV-to-JSON cleaner, and SQLite audit ledger built with **Python 3.12**.

## Overview

`sha256-file-deduplicator` pairs an I/O-frugal content scanner (grouping by byte size before reading streams) with a tabular CSV sanitiser and persistent workflow audit table.

## Features

- **Size-before-hash scanning**: `scan_duplicates()` groups files by `st_size` first and only hashes `64 KiB` chunks when two or more regular files share the same byte count, while skipping symlinks and unreadable `OSError` entries cleanly.
- **Ragged-CSV safe cleaning**: `sanitize_and_export_csv()` validates expected headers, trims whitespace, rejects incomplete or extra-column ragged rows cleanly, and removes duplicates case-insensitively on a chosen key.
- **Audit ledger**: `AuditLedger` records processed counts, affected counts, timestamps, and structured JSON run summaries into SQLite.
- **Installable CLI**: Provides the `sha256-dedupe` command with `scan` and `sanitize` subcommands.

## Technology Stack

- Python 3.11+ (tested on Python 3.12)
- Python standard library (`hashlib`, `csv`, `sqlite3`, `pathlib`, `argparse`)
- pytest, Ruff

## Installation

```bash
pip install -e ".[dev]"
```

## Usage Examples

Scan a directory for duplicate files:

```bash
sha256-dedupe scan ./documents
```

Clean a CSV export into deduplicated JSON:

```bash
sha256-dedupe sanitize accounts.csv cleaned.json --required id email team --key email
```

## Technical Implementation Details

- Grouping files by size first means unique files never touch SHA-256 hashing (`O(1)` stat check instead of full linear read).
- `csv.DictReader` stores overflow columns beyond the header under key `None`; checking `None in raw_row` filters ragged rows safely before trimming strings.

## Project Structure

```text
sha256-file-deduplicator/
├── src/automation_toolkit/
│   ├── __init__.py
│   └── workflows.py
├── tests/
│   └── test_workflows.py
├── pyproject.toml
└── requirements.txt
```

## Testing

```bash
ruff check .
pytest -v
```

## Known Limitations & Future Improvements

- `scan_duplicates()` reports reclaimable space and does not delete or hard-link duplicates automatically; adding an explicit `--hardlink` or `--quarantine <dir>` workflow with dry-run confirmation is the next planned extension.
- CSV sanitisation accumulates unique cleaned records in memory before formatting sorted JSON; streaming JSON Lines (`.jsonl`) output would handle arbitrarily large inputs in constant RAM.
