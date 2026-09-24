"""Tests for rebuild_urls.py (stdlib unittest; run from the repo root with
python3 -m unittest discover -s scripts -v)."""

from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import rebuild_urls as ru

SCRIPT = str(Path(__file__).resolve().parent / "rebuild_urls.py")
VECTORS_PATH = Path(__file__).resolve().parent.parent / "go/testdata/vectors.json"
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
SIG64 = ru.b64url_encode(bytes(range(64)))


def cred_args(c: dict) -> tuple[str, str, str, str]:
    return c["recipient"], c["honor"], c["detail"], c["date"]


def log_record(recipient: str, honor: str, detail: str, date: str, sig: str) -> dict:
    payload = ru.canonical_payload(recipient, honor, detail, date)
    return {
        "timestamp": "2026-03-13T10:00:00Z",
        "recipient": recipient,
        "honor": honor,
        "detail": detail,
        "date": date,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_b64url": sig,
    }


def vector_record(v: dict) -> dict:
    return log_record(*cred_args(v["credential"]), v["signature_b64url"])


def expected_row(v: dict) -> dict:
    c = v["credential"]
    return {
        "name": c["recipient"],
        "honor": c["honor"],
        "detail": c["detail"],
        "date": c["date"],
        "url": v["url"],
    }


def csv_line(v: dict) -> str:
    return f"{v['payload_b64url']},{v['signature_b64url']}"


def run(*args: str) -> subprocess.CompletedProcess:
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    assert "Traceback" not in r.stderr, r.stderr
    return r


def read_rows(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


class EncodingTest(unittest.TestCase):
    def test_vector_parity(self):
        for v in VECTORS:
            with self.subTest(v["name"]):
                payload = ru.canonical_payload(*cred_args(v["credential"]))
                self.assertEqual(payload.hex(), v["canonical_hex"])
                self.assertEqual(ru.b64url_encode(payload), v["payload_b64url"])
                sig = ru.b64url_decode(v["signature_b64url"])
                self.assertEqual(ru.build_url(payload, sig), v["url"])

    def test_nfd_input_normalized(self):
        v = next(v for v in VECTORS if v["name"] == "nfc_edge_case")
        c = v["credential"]
        nfd_detail = "re\u0301sume\u0301"
        payload = ru.canonical_payload("Cafe\u0301", c["honor"], nfd_detail, c["date"])
        self.assertEqual(payload.hex(), v["canonical_hex"])

    def test_escapes(self):
        payload = ru.canonical_payload('a"b\\c', "h", "x\n\ty\x1b", "d")
        self.assertIn(b'"recipient":"a\\"b\\\\c"', payload)
        self.assertIn(b'"detail":"x\\n\\ty\\u001b"', payload)

    def test_b64url_decode(self):
        self.assertEqual(ru.b64url_decode("AAE"), b"\x00\x01")
        self.assertEqual(ru.b64url_decode("AAE="), b"\x00\x01")
        for bad in ("AA+E", "AA&E", "AA/E", "AA E", "AA=E"):
            with self.subTest(bad):
                with self.assertRaises(ValueError):
                    ru.b64url_decode(bad)
        with self.assertRaises(ValueError):
            ru.b64url_decode("AAAAA")  # len % 4 == 1
        with self.assertRaises(TypeError):
            ru.b64url_decode(123)

    def test_build_url_rejects_wrong_sig_length(self):
        with self.assertRaises(ValueError):
            ru.build_url(b"{}", bytes(63))


class RowFromPayloadTest(unittest.TestCase):
    def test_vectors(self):
        for v in VECTORS:
            with self.subTest(v["name"]):
                row = ru.row_from_payload(v["payload_b64url"], v["signature_b64url"])
                self.assertEqual(row, expected_row(v))

    def assert_rejected(self, obj_or_bytes, sig: str = SIG64):
        raw = obj_or_bytes
        if not isinstance(raw, bytes):
            raw = json.dumps(
                raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        with self.assertRaises(ru.ROW_ERRORS):
            ru.row_from_payload(ru.b64url_encode(raw), sig)

    def test_rejections(self):
        base = dict(VECTORS[0]["credential"])
        cases = {
            "version true": {**base, "version": True},
            "version 1.0": {**base, "version": 1.0},
            "version 2": {**base, "version": 2},
            "extra key": {**base, "extra": "x"},
            "missing key": {k: val for k, val in base.items() if k != "detail"},
            "non-string field": {**base, "honor": 5},
            "non-NFC": {**base, "recipient": "Cafe\u0301"},
            "not an object": [],
            "whitespace": json.dumps(base, sort_keys=True).encode(),
            "invalid utf-8": b"\xff\xfe",
        }
        for name, obj in cases.items():
            with self.subTest(name):
                self.assert_rejected(obj)

    def test_rejects_bad_encoding(self):
        v = VECTORS[0]
        p, s = v["payload_b64url"], v["signature_b64url"]
        for name, (pp, ss) in {
            "plus in payload": ("+" + p[1:], s),
            "ampersand in signature": (p, s[:-1] + "&"),
            "len%4==1": (p + "A" * (4 - len(p) % 4 + 1), s),
            "63-byte signature": (p, ru.b64url_encode(bytes(63))),
        }.items():
            with self.subTest(name):
                with self.assertRaises(ru.ROW_ERRORS):
                    ru.row_from_payload(pp, ss)


class RowFromLogRecordTest(unittest.TestCase):
    def test_vectors(self):
        for v in VECTORS:
            with self.subTest(v["name"]):
                row = ru.row_from_log_record(vector_record(v))
                self.assertEqual(row, expected_row(v))

    def test_rejections(self):
        good = vector_record(VECTORS[0])
        cases = {
            "tampered field": {**good, "honor": "Other"},
            "missing field": {k: val for k, val in good.items() if k != "date"},
            "int signature": {**good, "signature_b64url": 123},
            "short signature": {**good, "signature_b64url": "AAAA"},
            "not a dict": ["x"],
        }
        for name, rec in cases.items():
            with self.subTest(name):
                with self.assertRaises(ru.ROW_ERRORS):
                    ru.row_from_log_record(rec)


class ReasonTest(unittest.TestCase):
    def test_messages(self):
        self.assertEqual(ru._reason(KeyError("date")), "missing field 'date'")
        err = UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed")
        self.assertEqual(ru._reason(err), "invalid Unicode text")
        self.assertEqual(ru._reason(ValueError("boom")), "boom")
        self.assertEqual(ru._reason(TypeError()), "TypeError")

    def test_lone_surrogate_payload_rejected(self):
        raw = b'{"date":"d","detail":"\\ud800","honor":"h","recipient":"r","version":1}'
        with self.assertRaises(UnicodeEncodeError):
            ru.row_from_payload(ru.b64url_encode(raw), SIG64)


class CliTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name: str, data: str | bytes) -> Path:
        path = self.dir / name
        if isinstance(data, str):
            data = data.encode("utf-8")
        path.write_bytes(data)
        return path


class PayloadModeTest(CliTestBase):
    def test_prints_url(self):
        v = VECTORS[1]
        p, s = v["payload_b64url"], v["signature_b64url"]
        r = run(f"--payload={p}", f"--signature={s}")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, v["url"] + "\n")

    def test_signature_starting_with_dash(self):
        v = VECTORS[0]
        sig = ru.b64url_encode(b"\xf8" + bytes(63))
        self.assertTrue(sig.startswith("-"))
        r = run(f"--payload={v['payload_b64url']}", f"--signature={sig}")
        self.assertEqual(r.returncode, 0)
        expected = f"{ru.VERIFY_BASE_URL}?p={v['payload_b64url']}&s={sig}\n"
        self.assertEqual(r.stdout, expected)

    def test_bad_payload(self):
        r = run("--payload=W10", f"--signature={SIG64}")  # W10 is "[]"
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, "")
        self.assertIn("error:", r.stderr)

    def test_usage_errors(self):
        log = self.write("issuances.json", "[]")
        txt = self.write("in.txt", "")
        cases = {
            "payload only": ["--payload=abc"],
            "signature only": ["--signature=abc"],
            "nothing": [],
            "payload with file": [str(log), "--payload=a", "--signature=b"],
            "-o in payload mode": ["--payload=a", "--signature=b", "-o", "x.csv"],
            "unknown extension": [str(txt)],
        }
        for name, args in cases.items():
            with self.subTest(name):
                r = run(*args)
                self.assertEqual(r.returncode, 2)
                self.assertEqual(r.stdout, "")
        self.assertFalse((self.dir / "in-urls.csv").exists())


class LogFileTest(CliTestBase):
    def test_round_trip(self):
        extra = log_record(
            'Jane, "JJ" Roe', "Honor", 'For "valor", and more', "2026-04-01", SIG64
        )
        records = [vector_record(v) for v in VECTORS] + [extra]
        log = self.write("issuances.json", json.dumps(records))
        r = run(str(log))
        self.assertEqual(r.returncode, 0, r.stderr)
        out = self.dir / "issuances-urls.csv"
        self.assertTrue(out.read_bytes().startswith(b"\xef\xbb\xbf"))
        rows = read_rows(out)
        n = len(VECTORS)
        self.assertEqual(rows[:n], [expected_row(v) for v in VECTORS])
        self.assertEqual(rows[n]["name"], 'Jane, "JJ" Roe')
        self.assertEqual(rows[n]["detail"], 'For "valor", and more')
        self.assertEqual(rows[n]["url"], ru.row_from_log_record(extra)["url"])
        self.assertIn(f"Wrote {n + 1} rows", r.stderr)

    def test_tampered_entry_skipped(self):
        records = [vector_record(v) for v in VECTORS]
        records[1]["detail"] = "tampered"
        out = self.dir / "custom.csv"
        r = run(str(self.write("log.JSON", json.dumps(records))), "-o", str(out))
        self.assertEqual(r.returncode, 1)
        self.assertIn("entry 2:", r.stderr)
        self.assertNotIn("tampered", r.stderr)
        self.assertIn("skipped 1.", r.stderr)
        expected = [expected_row(v) for i, v in enumerate(VECTORS) if i != 1]
        self.assertEqual(read_rows(out), expected)

    def test_all_skipped_writes_header_only(self):
        log = self.write("issuances.json", json.dumps([{"recipient": "x"}]))
        r = run(str(log))
        self.assertEqual(r.returncode, 1)
        out = self.dir / "issuances-urls.csv"
        with open(out, encoding="utf-8-sig", newline="") as f:
            self.assertEqual(f.read(), "name,honor,detail,date,url\r\n")


class CsvFileTest(CliTestBase):
    def test_good_file(self):
        lines = ["id,payload,signature,notes"]
        for i, v in enumerate(VECTORS):
            lines.append(f"{i}, {v['payload_b64url']} ,{v['signature_b64url']},n")
        lines.insert(2, ",,,")
        src = self.write("in.csv", "\r\n".join(lines) + "\r\n")
        r = run(str(src))
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = read_rows(self.dir / "in-urls.csv")
        self.assertEqual(rows, [expected_row(v) for v in VECTORS])
        self.assertIn("skipped 0.", r.stderr)

    def test_excel_bom_on_payload_column(self):
        v = VECTORS[0]
        src = self.write("in.csv", f"\ufeffpayload,signature\r\n{csv_line(v)}\r\n")
        r = run(str(src))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read_rows(self.dir / "in-urls.csv"), [expected_row(v)])

    def test_blank_row_with_extra_cell(self):
        v = VECTORS[0]
        src = self.write("in.csv", f"payload,signature\n,,\n{csv_line(v)}\n")
        r = run(str(src))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read_rows(self.dir / "in-urls.csv"), [expected_row(v)])

    def test_bad_row_skipped(self):
        v = VECTORS[0]
        good = csv_line(v)
        src = self.write("in.csv", f"payload,signature\n{good}\nW10,{SIG64}\n{good}\n")
        r = run(str(src))
        self.assertEqual(r.returncode, 1)
        self.assertIn("line 3:", r.stderr)
        self.assertIn("Wrote 2 rows", r.stderr)
        self.assertIn("skipped 1.", r.stderr)
        self.assertEqual(read_rows(self.dir / "in-urls.csv"), [expected_row(v)] * 2)

    def test_short_row_skipped(self):
        src = self.write("in.csv", "payload,signature\nabc\n")
        r = run(str(src))
        self.assertEqual(r.returncode, 1)
        self.assertIn("line 2:", r.stderr)


class FileErrorTest(CliTestBase):
    def assert_file_error(self, src: Path, hint: str = "") -> None:
        r = run(str(src))
        self.assertEqual(r.returncode, 1)
        self.assertIn("error:", r.stderr)
        self.assertIn(hint, r.stderr)
        self.assertEqual(r.stdout, "")
        self.assertEqual(list(self.dir.glob("*-urls.csv")), [])

    def test_bad_json(self):
        self.assert_file_error(self.write("a.json", "[{"))

    def test_non_list_json(self):
        self.assert_file_error(self.write("a.json", "{}"), "JSON array")

    def test_empty_csv(self):
        self.assert_file_error(self.write("a.csv", ""), "missing column")

    def test_csv_missing_columns(self):
        self.assert_file_error(self.write("a.csv", "payload,sig\nx,y\n"), "signature")

    def test_csv_field_too_large(self):
        big = "x" * (csv.field_size_limit() + 1)
        self.assert_file_error(self.write("a.csv", f"payload,signature\n{big},y\n"))

    def test_cp1252_csv(self):
        src = self.write("a.csv", b"payload,signature\n\xe9,x\n")
        self.assert_file_error(src, "CSV UTF-8")

    def test_non_utf8_json_has_no_csv_hint(self):
        r = run(str(self.write("a.json", b'["\xe9"]')))
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("CSV UTF-8", r.stderr)

    def test_missing_input(self):
        self.assert_file_error(self.dir / "nope.json")

    def test_existing_output_untouched(self):
        v = VECTORS[0]
        src = self.write("in.csv", f"payload,signature\n{csv_line(v)}\n")
        out = self.write("in-urls.csv", b"keep me")
        r = run(str(src))
        self.assertEqual(r.returncode, 1)
        self.assertIn("delete it or pass -o", r.stderr)
        self.assertEqual(out.read_bytes(), b"keep me")

    def test_output_is_input(self):
        src = self.write("in.csv", "payload,signature\n")
        r = run(str(src), "-o", str(src))
        self.assertEqual(r.returncode, 1)
        self.assertIn("choose another -o", r.stderr)
        self.assertEqual(src.read_text(encoding="utf-8"), "payload,signature\n")


if __name__ == "__main__":
    unittest.main()
