#!/usr/bin/env python3
"""One-command CIS GCP audit orchestrator (read-only by default)."""
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from audit_engine import AuditEngine, CONTROLS

HERE = Path(__file__).resolve().parent


def load_config(filename: Path) -> dict:
    data = json.loads(filename.read_text(encoding="utf-8"))
    if not data.get("project_id") or not data.get("controls"):
        raise ValueError("Missing project_id / controls in config.json")
    if len(data["controls"]) != len(set(data["controls"])):
        raise ValueError("Duplicate controls")
    unknown = set(data["controls"]) - CONTROLS.keys()
    if unknown:
        raise ValueError(f"Unsupported control IDs: {sorted(unknown)}")
    return data


def guard_project(project: str):
    if not shutil.which("gcloud"):
        raise RuntimeError("gcloud not found. Run in authenticated Google Cloud Shell")
    p = subprocess.run(["gcloud", "config", "get-value", "project"],
                       capture_output=True, text=True, timeout=20)
    active = p.stdout.strip()
    if p.returncode or active != project:
        raise RuntimeError(f"Project mismatch: configured={project}, active={active or 'UNSET'}; NO ACTION")


def audit(config: dict, root: Path, label: str):
    folder = root / label
    engine = AuditEngine(config, folder)
    rows = engine.execute()
    print(f"\nPROJECT: {config['project_id']}")
    print("CIS    STATUS    DETAILS")
    for row in rows:
        print(f"{row.cis:<6} {row.status:<9} {row.detail[:105]}")
    counts = {s: sum(r.status == s for r in rows) for s in ("PASS", "FAIL", "REVIEW", "N/A", "ERROR")}
    print("\nRESULTS: " + ", ".join(f"{x}={n}" for x,n in counts.items()))
    print(f"PASS-only report: {folder / 'PASS_ONLY_REPORT.md'}")
    print(f"Full audit:       {folder / 'results.csv'}")
    print(f"Evidence:         {folder / 'evidence'}")
    return rows


def guarded_remediation(args, config: dict, base: Path):
    playbooks = config.get("playbooks", {})
    if not args.control:
        print("Available manual-approved remediation playbooks:")
        for cid, p in playbooks.items():
            print(f"  CIS {cid}: {p}")
        print("No changes. Specify --control CIS_ID for preview.")
        return 0
    if args.control not in playbooks:
        raise ValueError(f"CIS {args.control} is not in the remediation allowlist")
    pb = (HERE / playbooks[args.control]).resolve()
    print(f"CONTROL: CIS {args.control} - {CONTROLS[args.control]}")
    print(f"PLAYBOOK: {pb}")
    print(f"PROJECT:  {config['project_id']}")
    print("DEFAULT:  NO CHANGES. The playbook itself has approve_change guard.")
    if not args.apply:
        print("PREVIEW ONLY. To apply, use --apply --reason 'approved change'.")
        if not pb.is_file():
            print("Note: playbook missing at this path; keep your existing file in ~/cis-gcp-audit/")
        return 0
    if not args.reason or len(args.reason.strip()) < 6:
        raise ValueError("--apply requires a meaningful --reason (>= 6 chars)")
    if not pb.is_file():
        raise FileNotFoundError(f"Playbook not found: {pb}")
    if not shutil.which("ansible-playbook"):
        raise RuntimeError("ansible-playbook not found")
    # A security change must have been explicitly approved by the project owner.
    phrase = f"APPLY {args.control} {config['project_id']}"
    print(f"\nWARNING: changing shared GCP resources could cause outages or charges.")
    print("Ansible script may modify more than one VPC/firewall target.")
    answer = input(f"Enter exactly '{phrase}' after owner approval: ").strip()
    if answer != phrase:
        print("Cancelled without applying changes.")
        return 2
    before = audit(config, base, "before_apply")
    current = next(r for r in before if r.cis == args.control)
    if current.status != "FAIL":
        print(f"STOP: CIS {args.control} is {current.status}, not FAIL; no remediation invoked.")
        return 2
    print("\nChecking playbook syntax...")
    syntax = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(pb), "--syntax-check"],
                            text=True, capture_output=True)
    (base / "ansible_syntax.txt").write_text(syntax.stdout + syntax.stderr, encoding="utf-8")
    if syntax.returncode:
        raise RuntimeError("Ansible syntax check failed. See ansible_syntax.txt")
    cmd = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(pb),
           "-e", "approve_change=true"]
    print("\nRunning authorized Ansible playbook...")
    with (base / "ansible_remediation.log").open("w", encoding="utf-8") as fh:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            print(line, end="")
            fh.write(line)
        exit_code = proc.wait()
    (base / "change_reason.txt").write_text(args.reason.strip() + "\n", encoding="utf-8")
    print("\nRe-auditing after Ansible execution...")
    try:
        after = audit(config, base, "after_apply")
    except Exception as exc:
        raise RuntimeError(f"Ansible exit={exit_code}; re-audit failed: {exc}") from exc
    updated = next(r for r in after if r.cis == args.control)
    if exit_code or updated.status != "PASS":
        print(f"REMEDIATION NEEDS REVIEW: ansible_exit={exit_code}, CIS {args.control}={updated.status}")
        return 1
    print(f"SUCCESS: CIS {args.control} FAIL -> PASS (project configuration scope)")
    return 0


def main():
    ap = argparse.ArgumentParser(description="CIS GCP: automated audit and explicitly-approved remediation")
    ap.add_argument("--mode", choices=("audit", "remediate"), default="audit")
    ap.add_argument("--config", type=Path, default=HERE / "config.json")
    ap.add_argument("--control", help="single CIS control for remediation preview/apply")
    ap.add_argument("--apply", action="store_true", help="apply one allowlisted playbook (interactive approval required)")
    ap.add_argument("--reason", help="reason / owner approval reference for change log")
    args = ap.parse_args()
    try:
        config = load_config(args.config.resolve())
        guard_project(config["project_id"])
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = HERE / "runs" / f"{stamp}_{os.getpid()}"
        if args.mode == "audit":
            if args.apply:
                raise ValueError("--apply only permitted with --mode remediate")
            rows = audit(config, output, "audit")
            # Fail-closed CI exit code: PASS-only report still produced.
            return 0 if all(r.status == "PASS" for r in rows) else 3
        if args.apply:
            output.mkdir(parents=True, exist_ok=True)
        return guarded_remediation(args, config, output)
    except (ValueError, RuntimeError, FileNotFoundError, KeyboardInterrupt) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
