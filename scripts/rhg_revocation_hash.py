#!/usr/bin/env python3
"""Print the revocation hash for an RHG credential verification URL.

The hash is SHA-256 of the raw payload bytes in the URL's `p` parameter,
lowercase hex -- the value that goes in verify/keys/revocations.json.

Usage:
    python3 scripts/rhg_revocation_hash.py 'https://verify.royalhouseofgeorgia.ge/?p=...&s=...'

~/.local/bin/rhg-revocation-hash can be a symlink to this file.
"""

import base64
import hashlib
import json
import re
import sys
from urllib.parse import parse_qs, urlsplit


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        params = parse_qs(urlsplit(sys.argv[1].strip()).query)
        if len(params.get("p", [])) != 1:
            raise ValueError("URL must contain exactly one p= parameter")
        p = params["p"][0].rstrip("=")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", p):
            raise ValueError("p= is not base64url")
        payload = base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))
        cred = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(hashlib.sha256(payload).hexdigest())
    # Echo what the hash identifies so the right credential gets revoked.
    print(f"  {cred.get('recipient')} | {cred.get('honor')} | {cred.get('date')}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
