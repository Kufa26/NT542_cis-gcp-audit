import csv
import json
import subprocess
from pathlib import Path

PROJECT = "project-2dcdd108-5e41-45e8-bed"
OUT = Path("report/compute")
OUT.mkdir(parents=True, exist_ok=True)

def run(*args):
    p = subprocess.run(
        ["gcloud", *args, "--format=json"],
        capture_output=True,
        text=True
    )
    if p.returncode:
        raise RuntimeError(p.stderr)
    return json.loads(p.stdout)

try:
    instances = run(
        "compute", "instances", "list",
        f"--project={PROJECT}"
    )

    project_info = run(
        "compute", "project-info", "describe",
        f"--project={PROJECT}"
    )

    project_meta = {
        x["key"]: x.get("value", "")
        for x in project_info.get(
            "commonInstanceMetadata", {}
        ).get("items", [])
    }

    results = []

    for item in instances:
        name = item["name"]
        zone = item["zone"].split("/")[-1]

        vm = run(
            "compute", "instances", "describe", name,
            f"--zone={zone}",
            f"--project={PROJECT}"
        )

        vm_meta = {
            x["key"]: x.get("value", "")
            for x in vm.get("metadata", {}).get("items", [])
        }

        block = vm_meta.get(
            "block-project-ssh-keys", ""
        ).lower() == "true"

        oslogin = vm_meta.get(
            "enable-oslogin",
            project_meta.get("enable-oslogin", "")
        ).lower() == "true"

        if block:
            status = "PASS"
            details = "Project-wide SSH keys blocked"
        elif oslogin:
            status = "REVIEW"
            details = "OS Login enabled; SSH metadata keys ignored"
        else:
            status = "FAIL"
            details = "Project-wide SSH keys not blocked"

        results.append([
            "4.3", status, name, zone, details
        ])

    if not instances:
        results.append([
            "4.3", "N/A", "", "",
            "No VM instances"
        ])

    path = OUT / "cis43_results.csv"
    with path.open(
        "w", newline="", encoding="utf-8"
    ) as f:
        writer = csv.writer(f)
        writer.writerow([
            "cis", "status", "instance", "zone", "details"
        ])
        writer.writerows(results)

    for row in results:
        print(" | ".join(row))

    print("Evidence:", path)

except Exception as e:
    print("AUDIT ERROR:", e)
    raise SystemExit(1)
