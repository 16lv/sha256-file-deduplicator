# sha256-file-deduplicator

Two-stage duplicate file scanner and CSV-to-JSON cleaner built in **Python 3.12**, with SQLite execution logging.

## Features

- **Size-filtered hashing**: `scan_duplicates()` groups files by byte length first and reads chunked SHA-256 hashes (`65536` bytes per read) only when at least two non-symlink files share a byte count, skipping unreadable paths safely.
- **CSV sanitisation & deduplication**: `sanitize_and_export_csv()` validates required headers, rejects incomplete or extra-column ragged rows, trims whitespace, deduplicates case-insensitively on `dedupe_key`, and writes deterministic JSON.
- **Audit log**: `AuditLedger` records scanned counts and affected records in SQLite.

## Quick Start

```bash
pip install -e ".[dev]"
ruff check .
pytest -v
```

Run from the terminal:

```bash
PYTHONPATH=src python -m automation_toolkit.workflows scan ./downloads
PYTHONPATH=src python -m automation_toolkit.workflows sanitize raw.csv clean.json --required id email --key email
```
