import csv
import json
import subprocess
from pathlib import Path

project = "project-2dcdd108-5e41-45e8-bed"
out = Path("report/dns")
out.mkdir(parents=True, exist_ok=True)

def gcloud(*args):
    p = subprocess.run(
        ["gcloud", *args,
         f"--project={project}", "--format=json"],
        capture_output=True, text=True
    )
    if p.returncode:
        raise RuntimeError(p.stderr)
    return json.loads(p.stdout)

def network_ref(url):
    if "/projects/" not in url:
        return None
    return url.split("/projects/", 1)[1].rstrip("/")

try:
    networks = gcloud("compute", "networks", "list")
    policies = gcloud("dns", "policies", "list")

    (out / "networks.json").write_text(
        json.dumps(networks, indent=2)
    )
    (out / "policies.json").write_text(
        json.dumps(policies, indent=2)
    )

    rows = []

    for network in networks:
        name = network["name"]
        self_link = network.get("selfLink", "")
        linked = []

        for policy in policies:
            policy_networks = policy.get("networks", [])

            if any(
                network_ref(n.get("networkUrl", "")) == network_ref(self_link) and network_ref(self_link) is not None
                for n in policy_networks
            ):
                linked.append(policy)

        enabled = any(
            p.get("enableLogging", False)
            for p in linked
        )

        status = "PASS" if enabled else "FAIL"
        rows.append([
            "2.13", status, name,
            ",".join(p["name"] for p in linked)
            or "No DNS policy",
            enabled
        ])

    if not networks:
        rows.append([
            "2.13", "N/A", "", "No VPC networks", False
        ])

    with (out / "cis213_results.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        writer = csv.writer(f)
        writer.writerow([
            "cis", "status", "network",
            "dns_policy", "logging_enabled"
        ])
        writer.writerows(rows)

    for row in rows:
        print(" | ".join(map(str, row)))

    print("Evidence: report/dns/cis213_results.csv")

except Exception as e:
    print("AUDIT ERROR:", e)
    raise SystemExit(1)
