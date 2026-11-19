import csv
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

project = "project-2dcdd108-5e41-45e8-bed"
out = Path("report/iam")
out.mkdir(parents=True, exist_ok=True)

def gcloud(*args):
    p = subprocess.run(
        ["gcloud", *args, "--format=json"],
        text=True, capture_output=True
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr)
    return json.loads(p.stdout)

try:
    accounts = gcloud(
        "iam", "service-accounts", "list",
        f"--project={project}"
    )

    policy = gcloud(
        "projects", "get-iam-policy", project
    )

    all_keys = []
    for sa in accounts:
        email = sa["email"]
        keys = gcloud(
            "iam", "service-accounts", "keys", "list",
            f"--iam-account={email}",
            f"--project={project}"
        )
        for key in keys:
            key["serviceAccountEmail"] = email
        all_keys.extend(keys)

    (out / "accounts.json").write_text(
        json.dumps(accounts, indent=2)
    )
    (out / "policy.json").write_text(
        json.dumps(policy, indent=2)
    )
    (out / "keys.json").write_text(
        json.dumps(all_keys, indent=2)
    )

    user_keys = [
        k for k in all_keys
        if k.get("keyType") == "USER_MANAGED"
    ]
    unknown_keys = [
        k for k in all_keys
        if k.get("keyType") not in
        ("USER_MANAGED", "SYSTEM_MANAGED")
    ]

    bindings = policy.get("bindings", [])

    admin_bindings = []
    risky_user_bindings = []
    group_bindings = []

    dangerous_roles = {
        "roles/owner", "roles/editor"
    }
    sa_roles = {
        "roles/iam.serviceAccountUser",
        "roles/iam.serviceAccountTokenCreator"
    }

    for b in bindings:
        role = b["role"]
        name = role.split("/")[-1].lower()

        for member in b.get("members", []):
            if member.startswith("serviceAccount:"):
                if (role in dangerous_roles or
                        "admin" in name):
                    admin_bindings.append((role, member))

            if role in sa_roles:
                if member.startswith("user:"):
                    risky_user_bindings.append((role, member))
                elif member.startswith("group:"):
                    group_bindings.append((role, member))

    expired_keys = []
    missing_dates = []
    now = datetime.now(timezone.utc)

    for key in user_keys:
        try:
            created = datetime.fromisoformat(
                key["validAfterTime"].replace("Z", "+00:00")
            )
            if (now - created).days > 90:
                expired_keys.append(key)
        except (KeyError, ValueError):
            missing_dates.append(key)

    results = [
        (
            "1.5",
            "REVIEW" if unknown_keys else (
                "FAIL" if user_keys else
                "PASS" if accounts else "N/A"
            ),
            f"{len(user_keys)} user-managed keys"
        ),
        (
            "1.6",
            "FAIL" if admin_bindings else (
                "PASS" if accounts else "N/A"
            ),
            f"{len(admin_bindings)} direct admin bindings"
        ),
        (
            "1.7",
            "FAIL" if risky_user_bindings else (
                "REVIEW" if group_bindings else "PASS"
            ),
            f"{len(risky_user_bindings)} direct user violations"
        ),
        (
            "1.8",
            "REVIEW" if unknown_keys or missing_dates else (
                "FAIL" if expired_keys else
                "PASS" if user_keys else "N/A"
            ),
            f"{len(expired_keys)} keys older than 90 days"
        )
    ]

    with (out / "results.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        writer = csv.writer(f)
        writer.writerow(["cis", "status", "details"])
        writer.writerows(results)

    print("CIS | STATUS | DETAILS")
    for cis, status, details in results:
        print(f"{cis} | {status} | {details}")

    print("Saved to report/iam/results.csv")
    print("Scope: direct Project bindings only")

except Exception as e:
    print("AUDIT ERROR:", e)
    raise SystemExit(1)
