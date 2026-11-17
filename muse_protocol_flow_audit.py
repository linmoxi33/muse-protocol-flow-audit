#!/usr/bin/env python3
"""muse-protocol-flow-audit

Offline conformance auditor for captured muse.ai onboarding / redemption
protocol transcripts.

It re-checks a captured session (a JSONL / JSON array of protocol steps, each
with the request it sent and the response it got) against the invariants that
duwqijlk/muse-protocol documents in its README:

  * the canonical step order and the steps that are mandatory;
  * per-step required request fields (restart.resume,
    confirm-otp.supports_muse_link_transparency, register-completion fields);
  * the cross-step flow of *dynamic* values: the ``tos.content_version``
    returned by ``confirm-otp`` must be the one sent in
    ``register-completion``, and the ``disclosure_text`` /
    ``disclosure_version`` parsed from the bootstrap document must be the ones
    sent in ``accept-tos`` (not the hard-coded constant);
  * expected HTTP status codes and the documented redeem-reason vocabulary.

No network access, no third-party dependencies: the input is a local file.

Exit codes: 0 = no finding at/above the fail-on threshold,
            1 = at least one finding at/above the threshold,
            2 = usage / input error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, datetime

TOOL = "muse-protocol-flow-audit"
UPSTREAM = "duwqijlk/muse-protocol"

# Canonical order documented in the upstream README "## 协议流程".
CANONICAL_ORDER = [
    "home",
    "restart",
    "send_otp",
    "confirm_otp",
    "register_completion",
    "bootstrap",
    "accept_tos",
    "invite",
    "vm_wake",
    "stateful_sharing",
    "redeem",
    "scratch_code",
]

# Steps the README marks as mandatory ("必须" / "先...否则...").
REQUIRED_STEPS = [
    "restart",
    "send_otp",
    "confirm_otp",
    "register_completion",
    "bootstrap",
    "accept_tos",
    "vm_wake",
    "redeem",
]

EXPECTED_STATUS = {
    "restart": {201},
    "send_otp": {200, 201},
    "confirm_otp": {200},
    "register_completion": {200},
    "bootstrap": {200},
    "accept_tos": {200},
    "invite": {200},
    "vm_wake": {200},
    "stateful_sharing": {200},
    "redeem": {200},
    "scratch_code": {200},
}

REDEEM_REASONS = {"redeemed", "already_redeemed", "used_up", "invalid"}

# Hard-coded disclosure body kept in upstream client.py as a documentation
# reference (upstream musepy/client.py, DISCLOSURE_TEXT_JA). accept-tos must
# use the server-dynamic text, never this constant.
DISCLOSURE_TEXT_JA = (
    "次に進むことで、Muse利用規約およびMetaのAI利用規約に同意するものとします。"
    "これには利用者の権利と責任に関する重要な情報が含まれています。"
    "プライバシーに関するMuseのアプローチについて詳しくはMuseプライバシーポリシーをご覧ください。"
)
SUPPORTED_DISCLOSURE_VERSION = "HATCH_ROW_v0"

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DISCLOSURE_TEXT_RE = re.compile(r'"disclosureText"\s*:\s*"((?:[^"\\]|\\.)*)"')
DISCLOSURE_VERSION_RE = re.compile(r'"disclosureVersion"\s*:\s*"((?:[^"\\]|\\.)*)"')


class AuditError(Exception):
    """Raised for usage / input problems (exit code 2)."""


def _severity_rank(sev):
    return {"error": 0, "warning": 1, "info": 2}.get(sev, 3)


def _finding(rule, severity, index, step, message, witness=None):
    f = {"rule": rule, "severity": severity, "index": index,
         "step": step, "message": message}
    if witness is not None:
        f["witness"] = witness
    return f


def load_transcript(path):
    """Load a JSONL or JSON-array transcript. Raises AuditError on bad input."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise AuditError(f"cannot read input file: {exc}")
    if not raw.strip():
        raise AuditError("input file is empty")

    stripped = raw.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise AuditError(f"input is not valid JSON: {exc}")
        if not isinstance(data, list):
            raise AuditError("JSON input must be an array of step records")
        return data

    records = []
    for lineno, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise AuditError(f"line {lineno} is not valid JSON: {exc}")
        if not isinstance(obj, dict):
            raise AuditError(f"line {lineno} is not a JSON object")
        records.append(obj)
    if not records:
        raise AuditError("input contains no step records")
    return records


def _step_of(record):
    step = record.get("step")
    return step if isinstance(step, str) else None


def _req_body(record):
    req = record.get("request") or {}
    if not isinstance(req, dict):
        return {}
    body = req.get("body")
    return body if isinstance(body, dict) else {}


def _resp_body(record):
    resp = record.get("response") or {}
    if not isinstance(resp, dict):
        return {}
    body = resp.get("body")
    return body if isinstance(body, dict) else {}


def _resp_text(record):
    resp = record.get("response") or {}
    if not isinstance(resp, dict):
        return ""
    for key in ("body_text", "text"):
        val = resp.get(key)
        if isinstance(val, str):
            return val
    return ""


def _resp_status(record):
    resp = record.get("response") or {}
    if not isinstance(resp, dict):
        return None
    status = resp.get("status")
    return status if isinstance(status, int) else None


def extract_disclosure(record):
    """Return (text, version) parsed from a bootstrap response document."""
    text = version = None
    resp = record.get("response") or {}
    if isinstance(resp, dict):
        if isinstance(resp.get("disclosure_text"), str):
            text = resp["disclosure_text"]
        if isinstance(resp.get("disclosure_version"), str):
            version = resp["disclosure_version"]
    body_text = _resp_text(record)
    if body_text:
        if text is None:
            m = DISCLOSURE_TEXT_RE.search(body_text)
            if m:
                text = m.group(1)
        if version is None:
            m = DISCLOSURE_VERSION_RE.search(body_text)
            if m:
                version = m.group(1)
    return text, version


def _parse_dob(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def _age_on(dob, today):
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


def audit(records, today=None):
    """Run all checks over normalized records. Returns a list of findings."""
    today = today or date.today()
    findings = []

    steps = []
    for idx, rec in enumerate(records):
        step = _step_of(rec)
        if step is None:
            findings.append(_finding(
                "RECORD_NO_STEP", "error", idx, None,
                "record has no string 'step' field",
                {"keys": sorted(rec.keys())}))
            continue
        if step not in CANONICAL_ORDER:
            findings.append(_finding(
                "UNKNOWN_STEP", "warning", idx, step,
                f"step '{step}' is not part of the documented protocol flow",
                {"canonical": CANONICAL_ORDER}))
        steps.append((idx, step, rec))

    # --- 1. canonical ordering (subsequence) ---
    last = -1
    for idx, step, _rec in steps:
        if step in CANONICAL_ORDER:
            pos = CANONICAL_ORDER.index(step)
            if pos < last:
                findings.append(_finding(
                    "FLOW_ORDER", "error", idx, step,
                    f"step '{step}' appears after a later-stage step; "
                    f"documented order is {CANONICAL_ORDER}",
                    {"position": pos, "previous_position": last}))
                break
            last = pos

    # --- 2. mandatory steps ---
    seen = {step for _idx, step, _rec in steps}
    for req in REQUIRED_STEPS:
        if req not in seen:
            idx = next((i for i, s, _r in steps if s is None), 0)
            findings.append(_finding(
                "MISSING_STEP", "error", idx, req,
                f"mandatory step '{req}' is absent from the transcript"))

    by_step = {}
    for idx, step, rec in steps:
        by_step.setdefault(step, (idx, rec))

    # --- 3. per-step request-field checks ---
    for idx, step, rec in steps:
        body = _req_body(rec)

        if step == "restart":
            if "resume" not in body:
                findings.append(_finding(
                    "RESTART_BODY", "error", idx, step,
                    "restart body must carry 'resume' (documented: {\"resume\": false})",
                    {"body_keys": sorted(body.keys())}))

        if step == "confirm_otp":
            if body.get("supports_muse_link_transparency") is not True:
                findings.append(_finding(
                    "CONFIRM_OTP_FIELD", "error", idx, step,
                    "confirm-otp must send supports_muse_link_transparency: true",
                    {"value": body.get("supports_muse_link_transparency")}))

        if step == "register_completion":
            missing = [k for k in
                       ("date_of_birth", "first_name", "last_name",
                        "tos_content_version", "remember_device")
                       if k not in body]
            if missing:
                findings.append(_finding(
                    "REGISTER_FIELDS", "error", idx, step,
                    "register-completion is missing required field(s): "
                    + ", ".join(missing),
                    {"missing": missing}))
            dob = _parse_dob(body.get("date_of_birth"))
            if body.get("date_of_birth") is not None and dob is None:
                findings.append(_finding(
                    "DOB_FORMAT", "error", idx, step,
                    "date_of_birth must be a YYYY-MM-DD date",
                    {"value": body.get("date_of_birth")}))
            elif dob is not None and _age_on(dob, today) < 18:
                findings.append(_finding(
                    "DOB_AGE_GATE", "error", idx, step,
                    f"date_of_birth implies age { _age_on(dob, today)} < 18; "
                    "upstream documents a 403 for this case",
                    {"date_of_birth": body.get("date_of_birth"),
                     "age": _age_on(dob, today)}))

        if step == "accept_tos":
            if not body.get("disclosure_text") or not body.get("disclosure_version"):
                findings.append(_finding(
                    "ACCEPT_TOS_DYNAMIC", "error", idx, step,
                    "accept-tos body must carry the server-dynamic "
                    "disclosure_text / disclosure_version",
                    {"body_keys": sorted(body.keys())}))
            else:
                if body.get("disclosure_text") == DISCLOSURE_TEXT_JA:
                    findings.append(_finding(
                        "ACCEPT_TOS_HARDCODED", "error", idx, step,
                        "accept-tos used the hard-coded disclosure text; the "
                        "README requires the server-dynamic text",
                        {"disclosure_version": body.get("disclosure_version")}))
                if body.get("disclosure_version") != SUPPORTED_DISCLOSURE_VERSION:
                    findings.append(_finding(
                        "DISCLOSURE_VERSION", "error", idx, step,
                        f"disclosure_version must be {SUPPORTED_DISCLOSURE_VERSION}; "
                        "upstream refuses to guess unknown versions",
                        {"disclosure_version": body.get("disclosure_version")}))

        if step == "vm_wake":
            problems = []
            if body.get("wake_trigger") != "mount":
                problems.append("wake_trigger != 'mount'")
            if body.get("away_ms") != 0:
                problems.append("away_ms != 0")
            if not isinstance(body.get("open_id"), str) or not UUID_RE.match(body["open_id"]):
                problems.append("open_id is not a uuid")
            if problems:
                findings.append(_finding(
                    "VM_WAKE_BODY", "error", idx, step,
                    "vm/wake body is not the documented mount payload: "
                    + "; ".join(problems),
                    {"body": body}))

    # --- 4. cross-step dynamic-value flow ---
    if "confirm_otp" in by_step and "register_completion" in by_step:
        _cidx, crec = by_step["confirm_otp"]
        tos = _resp_body(crec).get("tos")
        server_version = None
        if isinstance(tos, dict):
            server_version = tos.get("content_version")
        _ridx, rrec = by_step["register_completion"]
        req_version = _req_body(rrec).get("tos_content_version")
        if server_version and req_version and server_version != req_version:
            findings.append(_finding(
                "TOS_VERSION_FLOW", "error", _ridx, "register_completion",
                "register-completion sent a tos_content_version that differs "
                "from the one confirm-otp returned",
                {"confirm_otp": server_version, "register_completion": req_version}))

    if "bootstrap" in by_step and "accept_tos" in by_step:
        _bidx, brec = by_step["bootstrap"]
        text, version = extract_disclosure(brec)
        _aidx, arec = by_step["accept_tos"]
        abody = _req_body(arec)
        if text and abody.get("disclosure_text") and text != abody["disclosure_text"]:
            findings.append(_finding(
                "DISCLOSURE_FLOW", "error", _aidx, "accept_tos",
                "accept-tos disclosure_text differs from the value parsed out "
                "of the bootstrap document",
                {"bootstrap": text[:80], "accept_tos": abody["disclosure_text"][:80]}))
        if version and abody.get("disclosure_version") and version != abody["disclosure_version"]:
            findings.append(_finding(
                "DISCLOSURE_VERSION_FLOW", "error", _aidx, "accept_tos",
                "accept-tos disclosure_version differs from the bootstrap "
                "document's disclosureVersion",
                {"bootstrap": version, "accept_tos": abody.get("disclosure_version")}))

    # --- 5. ordering preconditions ---
    if "bootstrap" in by_step and "accept_tos" in by_step:
        if by_step["bootstrap"][0] > by_step["accept_tos"][0]:
            findings.append(_finding(
                "BOOTSTRAP_ORDER", "error", by_step["accept_tos"][0], "accept_tos",
                "accept_tos must be preceded by the session bootstrap"))

    if "vm_wake" in by_step and "redeem" in by_step:
        if by_step["vm_wake"][0] > by_step["redeem"][0]:
            findings.append(_finding(
                "VM_WAKE_ORDER", "error", by_step["redeem"][0], "redeem",
                "redeem must be preceded by vm/wake; without it redemption "
                "misreports 'invalid'"))

    # --- 6. status codes and redeem vocabulary ---
    for idx, step, rec in steps:
        if step not in EXPECTED_STATUS:
            continue
        status = _resp_status(rec)
        if status is None:
            continue
        if status not in EXPECTED_STATUS[step]:
            findings.append(_finding(
                "STATUS_EXPECTATION", "error", idx, step,
                f"expected status {sorted(EXPECTED_STATUS[step])} for "
                f"'{step}', got {status}",
                {"status": status}))

    if "redeem" in by_step:
        _ridx, rrec = by_step["redeem"]
        resp = rrec.get("response") or {}
        body = _resp_body(rrec)
        reason = body.get("reason")
        if isinstance(reason, str) and reason not in REDEEM_REASONS:
            findings.append(_finding(
                "REDEEM_REASON", "warning", _ridx, "redeem",
                f"redeem reason '{reason}' is outside the documented vocabulary",
                {"reason": reason, "vocabulary": sorted(REDEEM_REASONS)}))
        if status := _resp_status(rrec):
            if status == 200 and body.get("success") is False and not reason:
                findings.append(_finding(
                    "REDEEM_REASON", "warning", _ridx, "redeem",
                    "redeem returned success:false without a documented reason",
                    {"body": body}))

    return findings


def summarize(findings, fail_on):
    counts = {"error": 0, "warning": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    if fail_on == "never":
        triggered = []
    else:
        threshold = _severity_rank(fail_on)
        triggered = [f for f in findings if _severity_rank(f["severity"]) <= threshold]
    status = "fail" if triggered else "pass"
    return {"counts": counts, "triggered": len(triggered), "status": status}


def build_parser():
    p = argparse.ArgumentParser(
        prog=TOOL,
        description="Offline conformance auditor for captured muse.ai "
                    "protocol transcripts.")
    p.add_argument("input", help="transcript file (JSONL or JSON array)")
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON on stdout")
    p.add_argument("--fail-on", choices=["error", "warning", "never"],
                   default="error",
                   help="severity that makes the process exit 1 (default: error)")
    p.add_argument("--today", default=None,
                   help="reference date YYYY-MM-DD for the age gate "
                        "(default: system date)")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    today = None
    if args.today:
        today = _parse_dob(args.today)
        if today is None:
            print(f"{TOOL}: --today must be YYYY-MM-DD", file=sys.stderr)
            return 2

    try:
        records = load_transcript(args.input)
    except AuditError as exc:
        print(f"{TOOL}: {exc}", file=sys.stderr)
        return 2

    findings = audit(records, today=today)
    summary = summarize(findings, args.fail_on)

    if args.json:
        payload = {
            "tool": TOOL,
            "upstream": UPSTREAM,
            "input": args.input,
            "fail_on": args.fail_on,
            "today": args.today or today.isoformat(),
            "summary": summary,
            "findings": findings,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"{TOOL}: {summary['status'].upper()} "
              f"({summary['counts']['error']} error / "
              f"{summary['counts']['warning']} warning / "
              f"{summary['counts']['info']} info, "
              f"{summary['triggered']} at/above {args.fail_on})")
        for f in findings:
            loc = f"step[{f['index']}]" + (f" {f['step']}" if f["step"] else "")
            print(f"  [{f['severity']}] {f['rule']} {loc}: {f['message']}")

    return 1 if summary["status"] == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
