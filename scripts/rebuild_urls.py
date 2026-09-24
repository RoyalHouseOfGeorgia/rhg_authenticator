#!/usr/bin/env python3
"""Rebuild credential verification URLs from already-signed data.

Needs no YubiKey and does NOT verify signatures (the verify page does that).

Usage:
    python3 scripts/rebuild_urls.py --payload=P --signature=S
        Print the verification URL for one credential.

    python3 scripts/rebuild_urls.py INPUT_FILE [-o OUTPUT.csv]
        INPUT_FILE is either the app's audit log (issuances.json) or a CSV
        with "payload" and "signature" columns. Writes a CSV with columns
        name,honor,detail,date,url (default: <input stem>-urls.csv beside the
        input). Never overwrites an existing output file.

Always use the "=" form for --payload/--signature: signatures may start
with "-", which would otherwise be mistaken for an option.

Exit status: 0 success, 1 file error or any row skipped, 2 usage error.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

VERIFY_BASE_URL = "https://verify.royalhouseofgeorgia.ge/"
HEADER = ("name", "honor", "detail", "date", "url")
ROW_ERRORS = (KeyError, TypeError, ValueError)


def b64url_decode(s: str) -> bytes:
    """Decode unpadded (or padded) base64url, rejecting any other characters."""
    # Python's decoder silently drops invalid characters; the strict check also
    # keeps "&" and "#" out of the URL. fullmatch raises TypeError on non-str.
    if not re.fullmatch(r"[A-Za-z0-9_-]*=*", s):
        raise ValueError("invalid base64url characters")
    s = s.rstrip("=")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def canonical_payload(recipient: str, honor: str, detail: str, date: str) -> bytes:
    """Return the canonical JSON payload bytes, matching core.BuildPayload."""
    obj = {
        "date": unicodedata.normalize("NFC", date),
        "detail": unicodedata.normalize("NFC", detail),
        "honor": unicodedata.normalize("NFC", honor),
        "recipient": unicodedata.normalize("NFC", recipient),
        "version": 1,
    }
    # For this fixed ASCII key set this is byte-identical to Go's writer.
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def build_url(payload: bytes, sig: bytes) -> str:
    """Return the verification URL for a payload and 64-byte signature."""
    if len(sig) != 64:
        raise ValueError("signature must be 64 bytes")
    return f"{VERIFY_BASE_URL}?p={b64url_encode(payload)}&s={b64url_encode(sig)}"


def row_from_payload(p: str, s: str) -> dict[str, str]:
    """Build an output row from base64url payload and signature strings."""
    payload = b64url_decode(p)
    data = json.loads(payload)
    fields = (data["recipient"], data["honor"], data["detail"], data["date"])
    # Re-serializing and comparing rejects wrong version, extra/duplicate keys,
    # whitespace, non-NFC text and non-string fields in one check.
    if canonical_payload(*fields) != payload:
        raise ValueError("payload is not canonical")
    return _row(*fields, build_url(payload, b64url_decode(s)))


def row_from_log_record(rec: dict) -> dict[str, str]:
    """Build an output row from one audit-log record."""
    fields = (rec["recipient"], rec["honor"], rec["detail"], rec["date"])
    payload = canonical_payload(*fields)
    if hashlib.sha256(payload).hexdigest() != rec["payload_sha256"]:
        raise ValueError("payload_sha256 does not match record fields")
    return _row(*fields, build_url(payload, b64url_decode(rec["signature_b64url"])))


def _row(
    recipient: str, honor: str, detail: str, date: str, url: str
) -> dict[str, str]:
    return dict(zip(HEADER, (recipient, honor, detail, date, url)))


def _reason(e: Exception) -> str:
    """Short skip reason that never echoes field values."""
    if isinstance(e, KeyError):
        return f"missing field {e}"
    if isinstance(e, UnicodeError):
        return "invalid Unicode text"
    return str(e) or type(e).__name__


def rows_from_log(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    """Return (rows, skip messages) for an audit log file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("audit log must be a JSON array")
    rows, skipped = [], []
    for i, rec in enumerate(data, 1):
        try:
            rows.append(row_from_log_record(rec))
        except ROW_ERRORS as e:
            skipped.append(f"entry {i}: {_reason(e)}")
    return rows, skipped


def rows_from_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    """Return (rows, skip messages) for a CSV with payload/signature columns."""
    rows, skipped = [], []
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, restval="")
        missing = {"payload", "signature"} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing column(s): {', '.join(sorted(missing))}")
        for row in reader:
            p, s = row["payload"].strip(), row["signature"].strip()
            if not p and not s:
                continue
            try:
                rows.append(row_from_payload(p, s))
            except ROW_ERRORS as e:
                skipped.append(f"line {reader.line_num}: {_reason(e)}")
    return rows, skipped


def write_csv(out: Path, rows: list[dict[str, str]]) -> None:
    """Write rows to a new CSV file; fails if it already exists."""
    with open(out, "x", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns the process exit status."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "input", nargs="?", metavar="INPUT_FILE", help="issuances.json or a .csv"
    )
    parser.add_argument("--payload", metavar="P", help="base64url payload")
    parser.add_argument("--signature", metavar="S", help="base64url signature")
    parser.add_argument("-o", "--output", metavar="OUTPUT.csv", help="output CSV path")
    args = parser.parse_args(argv)

    if args.input is None:
        if args.payload is None or args.signature is None:
            parser.error("give INPUT_FILE, or both --payload and --signature")
        if args.output is not None:
            parser.error("-o is only valid with INPUT_FILE")
        try:
            row = row_from_payload(args.payload, args.signature)
        except ROW_ERRORS as e:
            print(f"error: {_reason(e)}", file=sys.stderr)
            return 1
        print(row["url"])
        return 0

    if args.payload is not None or args.signature is not None:
        parser.error("--payload/--signature cannot be combined with INPUT_FILE")
    src = Path(args.input)
    suffix = src.suffix.lower()
    if suffix == ".json":
        load = rows_from_log
    elif suffix == ".csv":
        load = rows_from_csv
    else:
        parser.error("INPUT_FILE must end in .json or .csv")
    out = Path(args.output) if args.output else src.with_name(f"{src.stem}-urls.csv")

    try:
        rows, skipped = load(src)
        write_csv(out, rows)
    except (OSError, ValueError, csv.Error) as e:
        msg = f"error: {e}"
        if isinstance(e, UnicodeDecodeError) and suffix == ".csv":
            msg += " (save the file as CSV UTF-8)"
        elif isinstance(e, FileExistsError):
            msg = f"error: {out} already exists; delete it or pass -o"
        print(msg, file=sys.stderr)
        return 1

    for msg in skipped:
        print(f"skipped {msg}", file=sys.stderr)
    print(f"Wrote {len(rows)} rows to {out}; skipped {len(skipped)}.", file=sys.stderr)
    return 1 if skipped else 0


if __name__ == "__main__":
    sys.exit(main())
