from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self


@dataclass(frozen=True)
class DuplicateGroup:
    sha256: str
    size_bytes: int
    canonical_path: str
    duplicate_paths: list[str]

    @property
    def reclaimable_bytes(self) -> int:
        return self.size_bytes * len(self.duplicate_paths)


@dataclass(frozen=True)
class DeduplicationReport:
    scanned_files: int
    unique_hashes: int
    duplicate_groups: list[DuplicateGroup]
    total_reclaimable_bytes: int
    skipped_unreadable: int = 0


@dataclass(frozen=True)
class TransformReport:
    input_rows: int
    valid_rows: int
    rejected_rows: int
    duplicates_removed: int
    output_path: str


class AuditLedger:
    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS workflow_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workflow_type TEXT NOT NULL,
                executed_at TEXT NOT NULL,
                processed_items INTEGER NOT NULL,
                affected_items INTEGER NOT NULL,
                details_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    def record_run(
        self,
        workflow_type: str,
        processed_items: int,
        affected_items: int,
        details: dict[str, Any],
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO workflow_runs (
                workflow_type, executed_at, processed_items, affected_items, details_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                workflow_type,
                datetime.now(UTC).isoformat(),
                processed_items,
                affected_items,
                json.dumps(details, sort_keys=True),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def list_runs(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM workflow_runs ORDER BY id DESC"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "workflow_type": r["workflow_type"],
                "executed_at": r["executed_at"],
                "processed_items": r["processed_items"],
                "affected_items": r["affected_items"],
                "details": json.loads(r["details_json"]),
            }
            for r in rows
        ]


def compute_sha256(path: Path, chunk_size: int = 65536) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def scan_duplicates(
    root_dir: Path,
    ledger: AuditLedger | None = None,
) -> DeduplicationReport:
    root = Path(root_dir)
    if not root.is_dir():
        raise NotADirectoryError(f"Root path is not a directory: {root}")

    by_size: dict[int, list[Path]] = {}
    scanned = 0
    skipped = 0

    for entry in sorted(root.rglob("*")):
        if entry.is_symlink() or not entry.is_file():
            continue
        try:
            size = entry.stat().st_size
        except OSError:
            skipped += 1
            continue
        scanned += 1
        by_size.setdefault(size, []).append(entry)

    by_hash: dict[str, tuple[int, list[Path]]] = {}
    unique_count = 0

    for size, paths in by_size.items():
        if len(paths) == 1:
            unique_count += 1
            continue
        for file_path in paths:
            try:
                digest = compute_sha256(file_path)
            except OSError:
                skipped += 1
                continue
            if digest not in by_hash:
                by_hash[digest] = (size, [file_path])
            else:
                by_hash[digest][1].append(file_path)

    groups: list[DuplicateGroup] = []
    for digest, (size, paths) in by_hash.items():
        unique_count += 1
        if len(paths) > 1:
            ordered = [str(p) for p in paths]
            groups.append(
                DuplicateGroup(
                    sha256=digest,
                    size_bytes=size,
                    canonical_path=ordered[0],
                    duplicate_paths=ordered[1:],
                )
            )

    total_reclaimable = sum(g.reclaimable_bytes for g in groups)
    report = DeduplicationReport(
        scanned_files=scanned,
        unique_hashes=unique_count,
        duplicate_groups=groups,
        total_reclaimable_bytes=total_reclaimable,
        skipped_unreadable=skipped,
    )

    if ledger is not None:
        ledger.record_run(
            workflow_type="deduplicate_scan",
            processed_items=scanned,
            affected_items=sum(len(g.duplicate_paths) for g in groups),
            details={"reclaimable_bytes": total_reclaimable, "groups": len(groups)},
        )

    return report


def sanitize_and_export_csv(
    input_csv: Path,
    output_json: Path,
    required_fields: list[str],
    dedupe_key: str,
    ledger: AuditLedger | None = None,
) -> TransformReport:
    """Stream CSV rows, trim values, drop incomplete or ragged rows, and write unique JSON."""
    src_csv = Path(input_csv)
    dst_json = Path(output_json)
    clean_dedupe_key = dedupe_key.strip()
    if not clean_dedupe_key:
        raise ValueError("dedupe_key must not be blank")
    clean_required = [f.strip() for f in required_fields if f.strip()]
    if not clean_required:
        raise ValueError("required_fields must contain at least one field name")
    if not src_csv.is_file():
        raise FileNotFoundError(f"Input CSV file not found: {src_csv}")

    input_rows = 0
    rejected_rows = 0
    duplicates_removed = 0
    seen_keys: set[str] = set()
    cleaned_records: list[dict[str, str]] = []

    with src_csv.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        header_fields = {col.strip() for col in (reader.fieldnames or ()) if col}
        expected_fields = set(clean_required) | {clean_dedupe_key}
        missing_headers = sorted(expected_fields - header_fields)
        if missing_headers:
            raise ValueError(f"CSV header missing required columns: {', '.join(missing_headers)}")

        for raw_row in reader:
            input_rows += 1
            # DictReader places extra comma columns under key None as a list; reject ragged rows safely
            if None in raw_row or any(not isinstance(v, str) for v in raw_row.values() if v is not None):
                rejected_rows += 1
                continue

            normalised = {
                k.strip(): (v.strip() if v is not None else "")
                for k, v in raw_row.items()
                if k is not None
            }
            if any(not normalised.get(field) for field in clean_required):
                rejected_rows += 1
                continue

            key_val = normalised.get(clean_dedupe_key, "").lower()
            if not key_val:
                rejected_rows += 1
                continue
            if key_val in seen_keys:
                duplicates_removed += 1
                continue

            seen_keys.add(key_val)
            cleaned_records.append(normalised)

    dst_json.parent.mkdir(parents=True, exist_ok=True)
    dst_json.write_text(
        json.dumps(cleaned_records, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    report = TransformReport(
        input_rows=input_rows,
        valid_rows=len(cleaned_records),
        rejected_rows=rejected_rows,
        duplicates_removed=duplicates_removed,
        output_path=str(dst_json),
    )

    if ledger is not None:
        ledger.record_run(
            workflow_type="csv_to_json_sanitize",
            processed_items=input_rows,
            affected_items=len(cleaned_records),
            details={
                "rejected_rows": rejected_rows,
                "duplicates_removed": duplicates_removed,
                "output_path": str(dst_json),
            },
        )

    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="File deduplication scanner and CSV-to-JSON cleaner."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="Find duplicate files under a folder")
    scan_cmd.add_argument("directory", type=Path, help="Folder to scan")

    csv_cmd = sub.add_parser("sanitize", help="Clean CSV rows into deduplicated JSON")
    csv_cmd.add_argument("input_csv", type=Path)
    csv_cmd.add_argument("output_json", type=Path)
    csv_cmd.add_argument("--required", nargs="+", required=True)
    csv_cmd.add_argument("--key", required=True)

    args = parser.parse_args(argv)
    if args.command == "scan":
        print(json.dumps(asdict(scan_duplicates(args.directory)), indent=2))
    else:
        print(
            json.dumps(
                asdict(
                    sanitize_and_export_csv(
                        args.input_csv,
                        args.output_json,
                        required_fields=args.required,
                        dedupe_key=args.key,
                    )
                ),
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
