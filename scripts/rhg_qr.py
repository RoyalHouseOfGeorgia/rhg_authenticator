#!/usr/bin/env python3
"""Write a QR code image for an RHG credential verification URL.

Needs segno (Debian: sudo apt install python3-segno; elsewhere: pip install segno).

Usage:
    python3 scripts/rhg_qr.py [--png] [-o FILE] URL
    python3 scripts/rhg_qr.py [--png] [-o FILE] --payload=P --signature=S

Writes SVG by default (rhg-qr.svg), or PNG with --png (rhg-qr.png).
Never overwrites an existing file. Use the "=" form for --payload/--signature:
signatures may start with "-".

Exit status: 0 success, 1 error, 2 usage error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rebuild_urls import ROW_ERRORS, _reason, row_from_payload


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns the process exit status."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("url", nargs="?", metavar="URL", help="verification URL")
    parser.add_argument("--payload", metavar="P", help="base64url payload")
    parser.add_argument("--signature", metavar="S", help="base64url signature")
    parser.add_argument("--png", action="store_true", help="write PNG instead of SVG")
    parser.add_argument("-o", "--output", metavar="FILE", help="output path")
    args = parser.parse_args(argv)

    pair = (args.payload, args.signature)
    if args.url is not None:
        if pair != (None, None):
            parser.error("give URL or --payload/--signature, not both")
        url = args.url.strip()
    elif None in pair:
        parser.error("give URL, or both --payload and --signature")
    else:
        try:
            url = row_from_payload(args.payload, args.signature)["url"]
        except ROW_ERRORS as e:
            print(f"error: {_reason(e)}", file=sys.stderr)
            return 1

    try:
        import segno  # only this tool needs it; rebuild_urls stays stdlib-only
    except ImportError:
        print("error: segno not installed (see --help)", file=sys.stderr)
        return 1

    out = Path(args.output or ("rhg-qr.png" if args.png else "rhg-qr.svg"))
    qr = segno.make(url, error="h")
    try:
        with out.open("xb") as f:
            if args.png:
                qr.save(f, kind="png", scale=20)
            else:
                # viewBox only (scales to any print size); white background like the app.
                qr.save(f, kind="svg", omitsize=True, light="white")
    except FileExistsError:
        print(f"error: {out} already exists", file=sys.stderr)
        return 1
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
