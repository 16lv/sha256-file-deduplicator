from __future__ import annotations

import json
from pathlib import Path

import pytest

from automation_toolkit.workflows import (
    AuditLedger,
    main,
    sanitize_and_export_csv,
    scan_duplicates,
)


def test_two_stage_duplicate_scanner_identifies_identical_payloads(tmp_path: Path) -> None:
    ledger = AuditLedger(":memory:")

    (tmp_path / "alpha.txt").write_bytes(b"duplicate-file-payload-sample-data-2026")
    (tmp_path / "beta_copy.txt").write_bytes(b"duplicate-file-payload-sample-data-2026")
    (tmp_path / "unique.txt").write_bytes(b"distinct-payload")

    report = scan_duplicates(tmp_path, ledger=ledger)
    assert report.scanned_files == 3
    assert report.unique_hashes == 2
    assert len(report.duplicate_groups) == 1
    assert report.duplicate_groups[0].reclaimable_bytes == 39

    runs = ledger.list_runs()
    assert len(runs) == 1
    assert runs[0]["workflow_type"] == "deduplicate_scan"


def test_two_stage_duplicate_scanner_handles_distinct_files_same_size(tmp_path: Path) -> None:
    ledger = AuditLedger(":memory:")

    (tmp_path / "file_a.bin").write_bytes(b"1234567890ABCDEF")
    (tmp_path / "file_b.bin").write_bytes(b"FEDCBA0987654321")

    report = scan_duplicates(tmp_path, ledger=ledger)
    assert report.scanned_files == 2
    assert len(report.duplicate_groups) == 0


def test_csv_sanitizer_handles_ragged_rows_duplicates_and_whitespace(tmp_path: Path) -> None:
    ledger = AuditLedger(":memory:")
    csv_file = tmp_path / "accounts.csv"
    out_json = tmp_path / "out" / "cleaned.json"

    csv_file.write_text(
        "id,email,team\n"
        "101, alice@example.org ,PLAT\n"
        "102,ALICE@example.org,PLAT\n"
        "103,,PLAT\n"
        "104,extra@example.org,DATA,unexpected_extra_column\n"
        "105,bob@example.org,SEC\n",
        encoding="utf-8",
    )

    report = sanitize_and_export_csv(
        input_csv=csv_file,
        output_json=out_json,
        required_fields=["id", "email", "team"],
        dedupe_key="email",
        ledger=ledger,
    )

    assert report.input_rows == 5
    assert report.valid_rows == 2
    assert report.rejected_rows == 2
    assert report.duplicates_removed == 1

    exported = json.loads(out_json.read_text(encoding="utf-8"))
    assert len(exported) == 2
    assert exported[0]["email"] == "alice@example.org"


def test_workflows_validate_directories_headers_and_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(NotADirectoryError):
        scan_duplicates(tmp_path / "does_not_exist")

    bad_csv = tmp_path / "incomplete.csv"
    bad_csv.write_text("id,name\n1,Test\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required columns"):
        sanitize_and_export_csv(
            input_csv=bad_csv,
            output_json=tmp_path / "out.json",
            required_fields=["id", "email"],
            dedupe_key="email",
        )

    assert main(["scan", str(tmp_path)]) == 0
    cli_report = json.loads(capsys.readouterr().out)
    assert cli_report["scanned_files"] == 1


def test_min_size_filter_skips_empty_placeholder_files(tmp_path: Path) -> None:
    (tmp_path / "empty1.txt").write_bytes(b"")
    (tmp_path / "empty2.txt").write_bytes(b"")
    (tmp_path / "real.txt").write_bytes(b"non-empty-content")

    with_empty = scan_duplicates(tmp_path, min_size_bytes=0)
    assert len(with_empty.duplicate_groups) == 1

    filtered = scan_duplicates(tmp_path, min_size_bytes=1)
    assert filtered.scanned_files == 1
    assert filtered.skipped_below_min_size == 2
    assert filtered.duplicate_groups == []
