import csv
import json
import subprocess
from pathlib import Path

PROJECT = "project-2dcdd108-5e41-45e8-bed"
OUT = Path("report/firewall")
OUT.mkdir(parents=True, exist_ok=True)

p = subprocess.run(
    ["gcloud", "compute", "firewall-rules", "list",
     f"--project={PROJECT}", "--format=json"],
    capture_output=True, text=True
)

if p.returncode:
    raise SystemExit("AUDIT ERROR: " + p.stderr)

rules = json.loads(p.stdout)
(OUT / "firewall_after.json").write_text(
    json.dumps(rules, indent=2)
)

def permits_port(rule, port):
    for allowed in rule.get("allowed", []):
        protocol = str(allowed.get("IPProtocol", "")).lower()
        if protocol not in ("tcp", "all", "6"):
            continue

        ports = allowed.get("ports", [])
        if protocol == "all" or not ports:
            return True

        for entry in ports:
            parts = str(entry).split("-")
            low = int(parts[0])
            high = int(parts[-1])
            if low <= port <= high:
                return True

    return False

def publicly_accessible(rule):
    ranges = rule.get("sourceRanges", [])
    if "0.0.0.0/0" in ranges or "::/0" in ranges:
        return True

    return (
        not ranges
        and not rule.get("sourceTags")
        and not rule.get("sourceServiceAccounts")
    )

results = []

for cis, port in [("3.6", 22), ("3.7", 3389)]:
    risky = []

    for rule in rules:
        if rule.get("disabled", False):
            continue
        if rule.get("direction") != "INGRESS":
            continue
        if not publicly_accessible(rule):
            continue
        if permits_port(rule, port):
            risky.append(rule["name"])

    status = "FAIL" if risky else "PASS"
    details = ",".join(risky) if risky else "No matching active public VPC firewall rules"

    results.append([cis, status, port, details])
    print(f"CIS {cis}: {status} | {details}")

with (OUT / "cis36_37_after.csv").open(
    "w", newline="", encoding="utf-8"
) as f:
    writer = csv.writer(f)
    writer.writerow(["cis", "status", "port", "details"])
    writer.writerows(results)

print("Evidence: report/firewall/cis36_37_after.csv")
