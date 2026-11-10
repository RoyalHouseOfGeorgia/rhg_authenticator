#!/usr/bin/env python3
"""Write a QR code image for an RHG credential verification URL.

Needs segno (Debian: sudo apt install python3-segno; elsewhere: pip install segno).

Usage:
    python3 scripts/rhg_qr.py [--png] [-o PATH] URL
    python3 scripts/rhg_qr.py [--png] [-o PATH] --payload=P --signature=S
    python3 scripts/rhg_qr.py [--png] [-o PATH] --log=issuances.json [SEARCH]

Writes SVG by default (rhg-qr.svg), or PNG with --png (rhg-qr.png), at error
correction level Q like the app. A URL gets the same checks as --payload and
--signature, so a truncated or edited one is refused. URLs over 625 characters
are refused.
Never overwrites an existing file. Use the "=" form for --payload/--signature:
signatures may start with "-".

With --log, lists the issuance log's credentials, most recently signed first
(only those whose recipient, honor, detail or date contains SEARCH, ignoring
case; quote a SEARCH of several words), asks which to generate (e.g. 1,3 or
all) and writes each into PATH, an existing folder (default: the current
folder), as <date>-<recipient>-<first 8 hex of the payload hash>.svg (.png
with --png). A credential signed more than once is listed once, as its newest
copy.

Exit status: 0 success, 1 error, 2 usage error. With --log, 1 also when any
picked file wasn't written (including one that already exists) or a log
record was skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import unicodedata
from pathlib import Path
from types import ModuleType
from urllib.parse import parse_qs, urlsplit

from rebuild_urls import (
    ROW_ERRORS,
    VERIFY_BASE_URL,
    _reason,
    canonical_payload,
    row_from_payload,
    rows_from_log,
)

# Same limit as the app (core.MaxVerifyURLLength): the longest URL that fits a
# printable QR code at error-correction level Q.
MAX_URL_LENGTH = 625

SEARCH_FIELDS = ("name", "honor", "detail", "date")


def checked_url(url: str) -> str:
    """Return url if it is exactly the verification URL its p and s rebuild to.

    Applies the --payload/--signature checks to a pasted URL, so a truncated or
    edited one is refused instead of printed. Raises one of ROW_ERRORS.
    """
    parts = urlsplit(url)
    if f"{parts.scheme}://{parts.netloc}{parts.path}" != VERIFY_BASE_URL:
        raise ValueError(
            f'not a verification URL (must start with "{VERIFY_BASE_URL}?")'
        )
    query = parse_qs(parts.query)
    if sorted(query) != ["p", "s"] or any(len(v) != 1 for v in query.values()):
        raise ValueError("URL must have exactly one p and one s parameter")
    rebuilt = row_from_payload(query["p"][0], query["s"][0])["url"]
    if rebuilt != url:
        raise ValueError("URL is not in the form the app writes")
    return rebuilt


def import_segno() -> ModuleType | None:
    """Return the segno module, or None after printing why it is missing."""
    try:
        import segno  # only this tool needs it; rebuild_urls stays stdlib-only
    except ImportError:
        print("error: segno not installed (see --help)", file=sys.stderr)
        return None
    return segno


def write_qr(segno: ModuleType, url: str, out: Path, png: bool) -> None:
    """Write url's QR code to the new file out; raises OSError if it can't.

    A write that fails part-way removes the file, so a later run doesn't skip
    a truncated image as already written.
    """
    qr = segno.make(url, error="q")  # level Q, as the app (skip2 qrcode.High)
    # Outside the try, so a file that was already there is never removed.
    f = out.open("xb")
    try:
        with f:  # closed before the unlink below, which Windows requires
            if png:
                qr.save(f, kind="png", scale=20)
            else:
                # viewBox only (scales to any print size); white background like the app.
                qr.save(f, kind="svg", omitsize=True, light="white")
    except BaseException:
        out.unlink(missing_ok=True)
        raise


def fold(s: str) -> str:
    """Normalize s for case-insensitive search."""
    return unicodedata.normalize("NFC", s.casefold())


def load_entries(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    """Return (entries newest first, one per credential, skip messages).

    Re-signing a credential with another YubiKey gives a new URL for the same
    payload; the newest is kept, as it carries the current key's signature.
    """
    rows, skipped = rows_from_log(path)
    seen: set[str] = set()
    entries = []
    for row in reversed(rows):
        payload = canonical_payload(
            row["name"], row["honor"], row["detail"], row["date"]
        )
        digest = hashlib.sha256(payload).hexdigest()
        if digest not in seen:
            seen.add(digest)
            entries.append({**row, "sha256": digest})
    return entries, skipped


def file_name(entry: dict[str, str], png: bool) -> str:
    """Return <date>-<recipient>-<hash prefix>.svg|png for an entry."""
    name = unicodedata.normalize("NFC", entry["name"])
    dashed = "".join(c if c.isalnum() else "-" for c in name)
    stem = re.sub("-+", "-", dashed)[:60].strip("-") or "credential"
    return f"{entry['date']}-{stem}-{entry['sha256'][:8]}.{'png' if png else 'svg'}"


def ask(count: int) -> list[int]:
    """Prompt until a valid pick; returns 0-based indexes in list order."""
    while True:
        answer = input("Generate which? (e.g. 1,3 or all): ").strip().casefold()
        if not answer:
            return []
        if answer == "all":
            return list(range(count))
        items = [item.strip() for item in answer.split(",")]
        if all(re.fullmatch(r"[0-9]+", i) and 1 <= int(i) <= count for i in items):
            return sorted({int(i) - 1 for i in items})
        print(f"Enter numbers from 1 to {count} separated by commas, or all.")


def log_mode(
    segno: ModuleType, log: Path, search: str | None, folder: Path, png: bool
) -> int:
    """List the log's credentials, ask which to write, and write them."""
    if not folder.is_dir():
        print(f"error: {folder} is not a folder", file=sys.stderr)
        return 1
    try:
        entries, skipped = load_entries(log)
    except (OSError, TypeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    for skip in skipped:
        print(f"skipped log record {skip.removeprefix('entry ')}", file=sys.stderr)
    if not entries:
        print(f"error: no usable entries in {log}", file=sys.stderr)
        return 1
    if search is not None:
        term = fold(search)
        entries = [e for e in entries if any(term in fold(e[k]) for k in SEARCH_FIELDS)]
        if not entries:
            print(f'error: no entries match "{search}"', file=sys.stderr)
            return 1

    # ljust counts code points, so Georgian or combining text lines up roughly.
    num_w = len(str(len(entries)))
    name_w = max(len(e["name"]) for e in entries)
    honor_w = max(len(e["honor"]) for e in entries)
    for n, e in enumerate(entries, 1):
        print(
            f"  {str(n).ljust(num_w)}  {e['date']}  {e['name'].ljust(name_w)}  "
            f"{e['honor'].ljust(honor_w)}  {e['detail']}"
        )
    try:
        picks = ask(len(entries))
    except (EOFError, KeyboardInterrupt):
        print()  # end the prompt line
        return 1
    if not picks:
        print("Nothing written.")
        return 1 if skipped else 0

    failed = False
    for i in picks:
        e = entries[i]
        if len(e["url"]) > MAX_URL_LENGTH:
            print(
                f"{e['date']} {e['name']}: URL is {len(e['url'])} characters; a "
                f"printable QR code fits at most {MAX_URL_LENGTH}, skipped",
                file=sys.stderr,
            )
            failed = True
            continue
        out = folder / file_name(e, png)
        try:
            write_qr(segno, e["url"], out, png)
        except FileExistsError:
            print(f"{out} exists, skipped", file=sys.stderr)
            failed = True
        except OSError as err:
            print(f"cannot write {out}: {err.strerror}", file=sys.stderr)
            failed = True
        else:
            print(out)
    return 1 if failed or skipped else 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns the process exit status."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "url",
        nargs="?",
        metavar="URL",
        help="URL, or with --log an optional search term",
    )
    parser.add_argument("--payload", metavar="P", help="base64url payload")
    parser.add_argument("--signature", metavar="S", help="base64url signature")
    parser.add_argument("--log", metavar="FILE", help="issuance log (issuances.json)")
    parser.add_argument("--png", action="store_true", help="write PNG instead of SVG")
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="output file, or an existing folder with --log",
    )
    args = parser.parse_args(argv)

    pair = (args.payload, args.signature)
    if args.log is not None:
        if pair != (None, None):
            parser.error("--log cannot be combined with --payload/--signature")
        segno = import_segno()
        if segno is None:
            return 1
        folder = Path(args.output or ".")
        return log_mode(segno, Path(args.log), args.url, folder, args.png)
    if args.url is not None and pair != (None, None):
        parser.error("give URL or --payload/--signature, not both")
    if args.url is None and None in pair:
        parser.error("give URL, or both --payload and --signature")
    try:
        if args.url is not None:
            url = checked_url(args.url.strip())
        else:
            url = row_from_payload(args.payload, args.signature)["url"]
    except ROW_ERRORS as e:
        print(f"error: {_reason(e)}", file=sys.stderr)
        return 1

    if len(url) > MAX_URL_LENGTH:
        print(
            f"error: URL is {len(url)} characters; a printable QR code fits at most "
            f"{MAX_URL_LENGTH} (the app refuses such a credential before signing)",
            file=sys.stderr,
        )
        return 1

    segno = import_segno()
    if segno is None:
        return 1
    out = Path(args.output or ("rhg-qr.png" if args.png else "rhg-qr.svg"))
    try:
        write_qr(segno, url, out, args.png)
    except FileExistsError:
        print(f"error: {out} already exists", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: cannot write {out}: {e.strerror}", file=sys.stderr)
        return 1
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
