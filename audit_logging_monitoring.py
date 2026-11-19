#!/usr/bin/env python3
"""Read-only CIS GCP Foundation v5 logging/monitoring audit (project scope).
Checks 2.1, 2.3, and 2.5-2.10. REVIEW means human verification required.
No resources are created/changed. Run in Google Cloud Shell with gcloud auth active.
"""
import argparse
import csv
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

RULES = {
    "2.5": ["cloudresourcemanager.googleapis.com", "roles/owner", "bindingDeltas"],
    "2.6": ["SetIamPolicy", "auditConfigDeltas"],
    "2.7": ["iam_role", "CreateRole", "DeleteRole", "UpdateRole", "UndeleteRole"],
    "2.8": ["gce_firewall_rule", "compute.firewalls.patch", "compute.firewalls.insert", "compute.firewalls.delete"],
    "2.9": ["gce_route", "compute.routes.delete", "compute.routes.insert"],
    "2.10": ["gce_network", "compute.networks.insert", "compute.networks.patch", "compute.networks.delete", "compute.networks.removePeering", "compute.networks.addPeering"],
}

def gcloud(project, out, label, args):
    cmd = ["gcloud", *args, f"--project={project}", "--format=json"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    if p.returncode:
        (out / f"{label}.error.txt").write_text(p.stderr or p.stdout, encoding="utf-8")
        return None, (p.stderr or p.stdout).strip().splitlines()[-1][:220]
    try:
        obj = json.loads(p.stdout or "[]")
    except ValueError:
        return None, f"Cannot parse {label} JSON"
    (out / f"{label}.json").write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return obj, None

def norm(s):
    return re.sub(r"\s+", "", s or "").lower()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--output", default="report/logging-before")
    args = ap.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    policy, pe = gcloud(args.project, out, "project_iam_policy", ["projects", "get-iam-policy", args.project])
    sinks, se = gcloud(args.project, out, "sinks", ["logging", "sinks", "list"])
    metrics, me = gcloud(args.project, out, "metrics", ["logging", "metrics", "list"])
    alerts, ae = gcloud(args.project, out, "alert_policies", ["monitoring", "policies", "list"])
    results=[]
    if pe:
        results.append(("2.1","ERROR",pe))
    else:
        acs=policy.get("auditConfigs", []) if isinstance(policy,dict) else []
        master=next((x for x in acs if x.get("service")=="allServices"),None)
        any_exempt=any(c.get("exemptedMembers") for x in acs for c in x.get("auditLogConfigs", []))
        types=set(c.get("logType") for c in master.get("auditLogConfigs",[])) if master else set()
        if any_exempt:
            results.append(("2.1","FAIL","Exempted members found in project audit configuration"))
        elif {"DATA_READ","DATA_WRITE","ADMIN_READ"}.issubset(types):
            results.append(("2.1","PASS","Project allServices has ADMIN_READ, DATA_READ, DATA_WRITE, without exemptions"))
        else:
            results.append(("2.1","REVIEW","No complete project-level allServices audit config; inherited/per-service policies not assessed"))
    if se:
        results.append(("2.3","ERROR",se))
    else:
        # Built-in sinks _Required and _Default don't establish independent SIEM/retention export.
        custom=[x for x in sinks if not str(x.get("name","")).split("/")[-1].startswith("_")]
        candidates=[x for x in custom if not x.get("disabled",False) and not x.get("filter","").strip() and x.get("destination") and not x.get("exclusions")]
        if candidates:
            results.append(("2.3","REVIEW",f"{len(candidates)} custom unfiltered enabled sink(s); verify destination exists and export works"))
        else:
            results.append(("2.3","REVIEW","No qualifying custom all-log sink in project; inherited sinks and destination not checked"))
    if me:
        for cid in RULES:
            results.append((cid,"ERROR",f"Cannot read log metrics: {me}"))
    elif ae:
        for cid in RULES:
            results.append((cid,"ERROR",f"Cannot read alert policies: {ae}"))
    else:
        for cid, tokens in RULES.items():
            matching=[]
            for m in metrics:
                f=norm(m.get("filter", ""))
                if all(norm(token) in f for token in tokens):
                    matching.append(m)
            if not matching:
                results.append((cid,"FAIL","No metric filter found with required CIS event tokens (project scope)"))
                continue
            matched_alerts=[]
            for metric in matching:
                name=metric.get("name","").split("/")[-1]
                target=f"logging.googleapis.com/user/{name}"
                for alert in alerts:
                    if alert.get("enabled",True) is False:
                        continue
                    conditions=alert.get("conditions",[])
                    if any(target in str(c.get("conditionThreshold",{}).get("filter","")) or target in json.dumps(c) for c in conditions):
                        matched_alerts.append(alert)
            if not matched_alerts:
                results.append((cid,"FAIL",f"{len(matching)} candidate metric(s) but no enabled linked alert policy"))
            else:
                results.append((cid,"REVIEW",f"{len(matching)} metric(s) + {len(matched_alerts)} linked alert(s); verify Boolean filter, threshold, notification channel"))
    with (out / "results.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.writer(f)
        w.writerow(["cis","status","details"])
        w.writerows(results)
    summary={"project":args.project,"timestamp_utc":datetime.now(timezone.utc).isoformat(),"scope":"direct project resources; partial verification", "counts":{k:sum(1 for r in results if r[1]==k) for k in ["PASS","FAIL","REVIEW","N/A","ERROR"]}}
    (out / "summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    print(f"PROJECT: {args.project}\nCIS   STATUS   DETAILS")
    for cid,status,detail in results:
        print(f"{cid:<5} {status:<8} {detail}")
    print(f"Evidence: {out}/results.csv, summary.json, *.json")
    print("NOTE: REVIEW = evidence incomplete, NOT PASS. No resources changed.")

if __name__ == "__main__":
    main()
