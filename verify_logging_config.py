#!/usr/bin/env python3
"""Read-only, configuration-level CIS GCP Foundation v5.0.0 2.5-2.10 verification.

Fetches current Log-based Metrics, Cloud Monitoring Alert Policies and notification
channels. Checks the six exact benchmark filters as deployed in the lab, rather
than simply checking for names. A PASS only verifies policy configuration;
notification delivery and ingestion are not tested.

Does not alter Google Cloud resources. Requires gcloud CLI and read permission.
"""
import argparse
import csv
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

RULES = {
    "2.5": {
        "metric": "cis_25_owner_change_count",
        "policy": "CIS 2.5 - Project Owner changes (NT542 Lab)",
        "filter": '''
          (protoPayload.serviceName="cloudresourcemanager.googleapis.com" AND
          (ProjectOwnership OR projectOwnerInvitee))
          OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND
          protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")
          OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND
          protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")
        ''',
    },
    "2.6": {
        "metric": "cis_26_audit_config_change_count",
        "policy": "CIS 2.6 - Audit configuration changes (NT542 Lab)",
        "filter": '''protoPayload.methodName="SetIamPolicy" AND
          protoPayload.serviceData.policyDelta.auditConfigDeltas:*''',
    },
    "2.7": {
        "metric": "cis_27_custom_role_change_count",
        "policy": "CIS 2.7 - Custom role changes (NT542 Lab)",
        "filter": '''resource.type="iam_role" AND
          (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR
          protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR
          protoPayload.methodName="google.iam.admin.v1.UpdateRole" OR
          protoPayload.methodName="google.iam.admin.v1.UndeleteRole")''',
    },
    "2.8": {
        "metric": "cis_28_firewall_change_count",
        "policy": "CIS 2.8 - Firewall rule changes (NT542 Lab)",
        "filter": '''resource.type="gce_firewall_rule" AND
          (protoPayload.methodName:"compute.firewalls.patch" OR
          protoPayload.methodName:"compute.firewalls.insert" OR
          protoPayload.methodName:"compute.firewalls.delete")''',
    },
    "2.9": {
        "metric": "cis_29_route_change_count",
        "policy": "CIS 2.9 - VPC route changes (NT542 Lab)",
        "filter": '''resource.type="gce_route" AND
          (protoPayload.methodName:"compute.routes.delete" OR
          protoPayload.methodName:"compute.routes.insert")''',
    },
    "2.10": {
        "metric": "cis_210_network_change_count",
        "policy": "CIS 2.10 - VPC network changes (NT542 Lab)",
        "filter": '''resource.type="gce_network" AND
          (protoPayload.methodName:"compute.networks.insert" OR
          protoPayload.methodName:"compute.networks.patch" OR
          protoPayload.methodName:"compute.networks.delete" OR
          protoPayload.methodName:"compute.networks.removePeering" OR
          protoPayload.methodName:"compute.networks.addPeering")''',
    },
}


def normalized(value):
    return re.sub(r"\s+", "", str(value or "")).lower()


def fetch(project, out, label, parts):
    command = ["gcloud", *parts, "--project=" + project, "--format=json"]
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Cannot run gcloud for " + label + ": " + str(exc)) from exc
    if process.returncode:
        error = (process.stderr or process.stdout).strip()
        (out / (label + ".error.txt")).write_text(error, encoding="utf-8")
        raise RuntimeError("gcloud " + label + " failed: " + error[-700:])
    try:
        data = json.loads(process.stdout or "[]")
    except ValueError as exc:
        raise RuntimeError("Invalid JSON returned for " + label) from exc
    if not isinstance(data, list):
        raise RuntimeError("Unexpected response for " + label + ": expected list")
    (out / (label + ".json")).write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return data


def check_threshold(condition, metric_name):
    th = condition.get("conditionThreshold") or {}
    if not th:
        return False, "Missing conditionThreshold"
    filt = normalized(th.get("filter", ""))
    wanted = normalized(
        f'metric.type="logging.googleapis.com/user/{metric_name}" AND resource.type="global"'
    )
    if filt != wanted:
        return False, "Threshold does not select the expected metric and global resource"
    if th.get("comparison") != "COMPARISON_GT":
        return False, "Comparison is not COMPARISON_GT"
    try:
        # Cloud Monitoring may omit a numeric zero in the JSON response.
        threshold = float(th.get("thresholdValue", 0))
    except (TypeError, ValueError):
        return False, "Invalid thresholdValue"
    if threshold != 0:
        return False, "Threshold is not zero"
    if str(th.get("duration", "0s")) not in {"0s", "0"}:
        return False, "Retest duration is not zero"
    aggs = th.get("aggregations", [])
    if not any(a.get("perSeriesAligner") == "ALIGN_SUM" and
               a.get("alignmentPeriod") == "60s" for a in aggs):
        return False, "Expected 60s ALIGN_SUM not present"
    try:
        triggers = int(th.get("trigger", {}).get("count", 1))
    except (TypeError, ValueError):
        return False, "Invalid trigger count"
    if triggers != 1:
        return False, "Trigger count is not one"
    return True, "Threshold/aggregation match"


def verify_one(control, rule, metrics, policies, channels, project):
    metric = next((m for m in metrics if m.get("name", "").split("/")[-1] == rule["metric"]), None)
    if not metric:
        return (control, "FAIL", "Missing log-based metric", "")
    if normalized(metric.get("filter")) != normalized(rule["filter"]):
        return (control, "REVIEW", "Metric exists but Log filter differs from CIS lab baseline", rule["metric"])
    if metric.get("disabled") is True:
        return (control, "FAIL", "Log-based metric is disabled", rule["metric"])
    name = rule["policy"]
    candidates = [p for p in policies if p.get("displayName") == name]
    if not candidates:
        return (control, "FAIL", "Missing alert policy", rule["metric"])
    issues = []
    unknown_channel = False
    for policy in candidates:
        if not policy.get("enabled", True):
            issues.append("Alert policy disabled")
            continue
        checks = [check_threshold(c, rule["metric"]) for c in policy.get("conditions", [])]
        if not checks or not any(ok for ok, _ in checks):
            issues.append("Condition mismatch: " + "; ".join(reason for ok, reason in checks if not ok)[:160])
            continue
        linked_channels = policy.get("notificationChannels", [])
        if not linked_channels:
            issues.append("No notification channel linked")
            continue
        matching = [ch for ch in channels
                    if ch.get("name") in linked_channels
                    and ch.get("name", "").startswith(f"projects/{project}/notificationChannels/")
                    and ch.get("type") == "email"
                    and ch.get("enabled", True) is True]
        if not matching:
            issues.append("No active email notification channel linked")
            continue
        verified = [ch for ch in matching if ch.get("verificationStatus") == "VERIFIED"]
        unverified = [ch for ch in matching if ch.get("verificationStatus") == "UNVERIFIED"]
        if not verified and unverified:
            issues.append("Linked email channel is UNVERIFIED")
            unknown_channel = True
            continue
        # Missing verificationStatus is normal for some channel responses;
        # it does not demonstrate actual email delivery either way.
        return (control, "PASS", "Configuration matches: metric filter, alert >0, 60s, linked active email; delivery not tested", rule["metric"])
    status = "REVIEW" if unknown_channel or issues else "FAIL"
    return (control, status, "; ".join(issues)[:260] or "Requires review", rule["metric"])


def assess(metrics, policies, channels, project):
    return [verify_one(control, rule, metrics, policies, channels, project)
            for control, rule in RULES.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", default="report/logging-verified")
    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    try:
        metrics = fetch(args.project, out, "metrics", ["logging", "metrics", "list"])
        policies = fetch(args.project, out, "alert_policies", ["monitoring", "policies", "list"])
        channels = fetch(args.project, out, "notification_channels", ["beta", "monitoring", "channels", "list"])
    except RuntimeError as exc:
        print("AUDIT ERROR:", exc, file=sys.stderr)
        return 1
    rows = assess(metrics, policies, channels, args.project)
    with (out / "results.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["cis", "status", "details", "metric"])
        writer.writerows(rows)
    summary = {
        "project": args.project,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "configuration-level verification of CIS 2.5-2.10; no live alert delivery test",
        "counts": {s: sum(row[1] == s for row in rows) for s in ("PASS", "FAIL", "REVIEW", "ERROR")}
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("PROJECT:", args.project)
    print("CIS    STATUS    DETAILS")
    for control, status, detail, _ in rows:
        print(f"{control:<6} {status:<9} {detail}")
    print("Evidence:", out / "results.csv")
    print("NOTE: PASS verifies configuration only, NOT actual message delivery or alert triggering.")
    print("NOTE: 2.1 and 2.3 are outside this program and remain REVIEW.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
