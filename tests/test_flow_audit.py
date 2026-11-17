"""Tests for muse-protocol-flow-audit.

Run: python3 -m unittest discover -s tests -v
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import muse_protocol_flow_audit as m  # noqa: E402

TODAY = date(2026, 11, 18)
TOS = "ntm_create_account:default_v1_meta_account_v3+docs_v2"
DYN = "\u6b21\u306b\u9032\u3080\u3053\u3068\u3067\u540c\u610f\u3057\u307e\u3059\u3002\u0032\u0030\u0032\u0036"
HARD = m.DISCLOSURE_TEXT_JA


def clean_records():
    return [
        {"step": "restart",
         "request": {"method": "POST", "body": {"resume": False}},
         "response": {"status": 201, "body": {"csrf_token": "c1"}}},
        {"step": "send_otp", "request": {"body": {"contact_point": "a@b.c"}},
         "response": {"status": 201, "body": {}}},
        {"step": "confirm_otp",
         "request": {"body": {"otp_code": "123456",
                              "supports_muse_link_transparency": True}},
         "response": {"status": 200,
                      "body": {"tos": {"content_version": TOS}}}},
        {"step": "register_completion",
         "request": {"body": {"date_of_birth": "1993-11-14",
                              "first_name": "Taro", "last_name": "Kondo",
                              "tos_content_version": TOS,
                              "remember_device": True}},
         "response": {"status": 200, "body": {}}},
        {"step": "bootstrap", "request": {},
         "response": {"status": 200, "disclosure_text": DYN,
                      "disclosure_version": "HATCH_ROW_v0"}},
        {"step": "accept_tos",
         "request": {"body": {"disclosure_text": DYN,
                              "disclosure_version": "HATCH_ROW_v0"}},
         "response": {"status": 200, "body": {}}},
        {"step": "vm_wake",
         "request": {"body": {"wake_trigger": "mount", "away_ms": 0,
                              "open_id": "33333333-3333-3333-3333-333333333333"}},
         "response": {"status": 200, "body": {}}},
        {"step": "redeem",
         "request": {"body": {"code": "X"}},
         "response": {"status": 200,
                      "body": {"success": True, "reason": "redeemed"}}},
    ]


def rules(records):
    return {f["rule"] for f in m.audit(records, today=TODAY)}


class TestRules(unittest.TestCase):
    def test_clean_has_no_findings(self):
        self.assertEqual(m.audit(clean_records(), today=TODAY), [])

    def test_missing_required_step(self):
        recs = [r for r in clean_records() if r["step"] != "vm_wake"]
        self.assertIn("MISSING_STEP", rules(recs))

    def test_out_of_order(self):
        recs = clean_records()
        recs[0], recs[1] = recs[1], recs[0]
        self.assertIn("FLOW_ORDER", rules(recs))

    def test_restart_body(self):
        recs = clean_records()
        recs[0]["request"]["body"] = {}
        self.assertIn("RESTART_BODY", rules(recs))

    def test_confirm_otp_flag(self):
        recs = clean_records()
        recs[2]["request"]["body"].pop("supports_muse_link_transparency")
        self.assertIn("CONFIRM_OTP_FIELD", rules(recs))

    def test_dob_age_gate(self):
        recs = clean_records()
        recs[3]["request"]["body"]["date_of_birth"] = "2013-11-14"
        out = m.audit(recs, today=TODAY)
        self.assertIn("DOB_AGE_GATE", {f["rule"] for f in out})
        gate = [f for f in out if f["rule"] == "DOB_AGE_GATE"][0]
        self.assertEqual(gate["witness"]["age"], 13)

    def test_tos_version_flow(self):
        recs = clean_records()
        recs[2]["response"]["body"]["tos"]["content_version"] = TOS + "-OLD"
        self.assertIn("TOS_VERSION_FLOW", rules(recs))

    def test_accept_tos_hardcoded(self):
        recs = clean_records()
        recs[5]["request"]["body"]["disclosure_text"] = HARD
        self.assertIn("ACCEPT_TOS_HARDCODED", rules(recs))

    def test_disclosure_version_unsupported(self):
        recs = clean_records()
        recs[5]["request"]["body"]["disclosure_version"] = "HATCH_ROW_v9"
        self.assertIn("DISCLOSURE_VERSION", rules(recs))
        self.assertIn("DISCLOSURE_VERSION_FLOW", rules(recs))

    def test_vm_wake_body(self):
        recs = clean_records()
        recs[6]["request"]["body"]["away_ms"] = 5
        self.assertIn("VM_WAKE_BODY", rules(recs))

    def test_vm_wake_order(self):
        recs = clean_records()
        recs[6], recs[7] = recs[7], recs[6]
        self.assertIn("VM_WAKE_ORDER", rules(recs))

    def test_redeem_reason_vocabulary(self):
        recs = clean_records()
        recs[7]["response"]["body"] = {"success": False, "reason": "expired"}
        self.assertIn("REDEEM_REASON", rules(recs))

    def test_status_expectation(self):
        recs = clean_records()
        recs[0]["response"]["status"] = 200
        self.assertIn("STATUS_EXPECTATION", rules(recs))

    def test_unknown_step_warning(self):
        recs = clean_records()
        recs.append({"step": "teleport", "request": {}, "response": {}})
        out = m.audit(recs, today=TODAY)
        self.assertIn("UNKNOWN_STEP", {f["rule"] for f in out})


class TestCliBehavior(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "muse_protocol_flow_audit.py"),
             *args], capture_output=True, text=True,
            cwd=ROOT, env={**os.environ, "PYTHONIOENCODING": "utf-8"})

    def _write(self, records):
        fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                         delete=False, encoding="utf-8")
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        fh.close()
        self.addCleanup(lambda: os.unlink(fh.name))
        return fh.name

    def test_cli_clean_exit_zero_and_json(self):
        path = self._write(clean_records())
        p = self._run(path, "--json", "--today", "2026-11-18")
        self.assertEqual(p.returncode, 0, p.stderr)
        doc = json.loads(p.stdout)
        self.assertEqual(doc["summary"]["status"], "pass")
        self.assertEqual(doc["summary"]["counts"]["error"], 0)

    def test_cli_broken_exit_one_and_json(self):
        recs = clean_records()
        recs[0]["request"]["body"] = {}
        recs[7]["response"]["body"] = {"success": False, "reason": "expired"}
        path = self._write(recs)
        p = self._run(path, "--json", "--today", "2026-11-18")
        self.assertEqual(p.returncode, 1, p.stderr)
        doc = json.loads(p.stdout)
        self.assertGreaterEqual(doc["summary"]["counts"]["error"], 1)
        self.assertGreaterEqual(doc["summary"]["counts"]["warning"], 1)

    def test_cli_fail_on_never_is_zero(self):
        recs = clean_records()
        recs[0]["request"]["body"] = {}
        path = self._write(recs)
        p = self._run(path, "--json", "--fail-on", "never", "--today", "2026-11-18")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertGreaterEqual(json.loads(p.stdout)["summary"]["counts"]["error"], 1)

    def test_cli_missing_file_exit_two(self):
        p = self._run("/tmp/definitely-not-here-42.jsonl", "--json")
        self.assertEqual(p.returncode, 2)

    def test_cli_bad_json_exit_two(self):
        fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        fh.write("{not json}\n")
        fh.close()
        self.addCleanup(lambda: os.unlink(fh.name))
        p = self._run(fh.name, "--json")
        self.assertEqual(p.returncode, 2)
        self.assertIn("not valid JSON", p.stderr)

    def test_cli_bad_today_exit_two(self):
        path = self._write(clean_records())
        p = self._run(path, "--today", "18-11-2026")
        self.assertEqual(p.returncode, 2)

    def test_cli_json_array_input(self):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8")
        json.dump(clean_records(), fh, ensure_ascii=False)
        fh.close()
        self.addCleanup(lambda: os.unlink(fh.name))
        p = self._run(fh.name, "--json", "--today", "2026-11-18")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["summary"]["status"], "pass")


if __name__ == "__main__":
    unittest.main()