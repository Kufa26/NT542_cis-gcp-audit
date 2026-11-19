"""CIS GCP project-scope read-only auditor. Python 3.10+, stdlib + gcloud only.

PASS means a specified configuration test passed; it is NOT an enterprise-wide
security attestation. Logs/notifications and inherited policies are not end-to-end
validated. Errors and REVIEW are never coerced into PASS.
"""
from __future__ import annotations

import csv
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONTROLS = {
    "1.5": "User-managed service account keys",
    "1.6": "Service account admin bindings",
    "1.7": "Service account user/token creator bindings",
    "2.5": "Project Owner change alert",
    "2.6": "Audit config change alert",
    "2.7": "Custom role change alert",
    "2.8": "Firewall rule change alert",
    "2.9": "Route change alert",
    "2.10": "Network change alert",
    "2.13": "Cloud DNS query logging",
    "2.14": "Cloud Asset API",
    "3.6": "No public ingress SSH",
    "3.7": "No public ingress RDP",
    "4.3": "Block project-wide SSH keys",
    "4.8": "Shielded VM vTPM and integrity monitoring",
    "4.9": "VMs without external IP",
    "5.1": "Cloud Storage public IAM access",
    "5.2": "Uniform bucket-level access",
}

@dataclass
class Result:
    cis: str
    status: str
    detail: str
    scope: str = "project"


class CommandFailure(RuntimeError):
    pass


class GCloud:
    def __init__(self, project: str, evidence: Path, timeout: int = 120):
        self.project = project
        self.evidence = evidence
        self.timeout = timeout
        self.cache: dict[tuple[str, ...], Any] = {}
        self.counter = 0
        evidence.mkdir(parents=True, exist_ok=True)

    def json(self, *args: str) -> Any:
        key = tuple(args)
        if key in self.cache:
            return self.cache[key]
        cmd = ["gcloud", *args, f"--project={self.project}", "--format=json", "--quiet"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise CommandFailure(str(e)) from e
        self.counter += 1
        label = f"{self.counter:02d}_" + "_".join(re.sub(r"[^a-z0-9]+", "_", x.lower()).strip("_")[:35] for x in args[:4])
        if p.returncode:
            self.evidence.joinpath(label + ".error.txt").write_text(p.stderr[:12000], encoding="utf-8")
            short = (p.stderr or p.stdout or "Unknown gcloud error").strip().splitlines()[-1]
            raise CommandFailure(f"gcloud {' '.join(args[:3])}: {short[:260]}")
        try:
            value = json.loads(p.stdout or "[]")
        except json.JSONDecodeError as e:
            raise CommandFailure(f"Invalid JSON for {' '.join(args[:3])}: {e}") from e
        self.evidence.joinpath(label + ".json").write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
        self.cache[key] = value
        return value


def true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


def short_name(path: str) -> str:
    return str(path or "").rstrip("/").split("/")[-1]


def network_ref(value: str) -> str | None:
    # Compute API and Cloud DNS API can use different hostnames.
    match = re.search(r"/projects/([^/]+)/global/networks/([^/?#]+)", value or "")
    return f"{match.group(1)}/{match.group(2)}" if match else None


def permitted_port(rule: dict, port: int) -> bool:
    for item in rule.get("allowed", []):
        proto = str(item.get("IPProtocol", "")).lower()
        if proto not in ("tcp", "all", "6"):
            continue
        if proto == "all" or not item.get("ports"):
            return True
        for candidate in item["ports"]:
            try:
                fields = str(candidate).split("-", 1)
                low, high = int(fields[0]), int(fields[-1])
            except ValueError:
                continue
            if low <= port <= high:
                return True
    return False


def is_public(rule: dict) -> bool:
    ranges = rule.get("sourceRanges", [])
    if "0.0.0.0/0" in ranges or "::/0" in ranges:
        return True
    return not ranges and not rule.get("sourceTags") and not rule.get("sourceServiceAccounts")


def public_bindings(policy: dict) -> list[str]:
    return [f"{b.get('role', '?')}:{m}"
            for b in policy.get("bindings", [])
            for m in b.get("members", [])
            if m in ("allUsers", "allAuthenticatedUsers")]


class AuditEngine:
    def __init__(self, config: dict, output: Path):
        self.config = config
        self.output = output
        self.project = config["project_id"]
        self.g = GCloud(self.project, output / "evidence")
        self.results: dict[str, Result] = {}

    def set(self, cid: str, status: str, detail: str, scope: str = "project") -> None:
        self.results[cid] = Result(cid, status, detail, scope)

    def group(self, controls: list[str], callback) -> None:
        try:
            callback()
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            for cid in controls:
                if cid not in self.results:
                    self.set(cid, "ERROR", msg)

    def iam(self):
        accounts = self.g.json("iam", "service-accounts", "list")
        user_keys = []
        for sa in accounts:
            email = sa.get("email")
            if not email:
                continue
            keys = self.g.json("iam", "service-accounts", "keys", "list", f"--iam-account={email}", "--managed-by=user")
            user_keys.extend((email, key.get("name", "")) for key in keys)
        self.set("1.5", "FAIL" if user_keys else "PASS", f"User-managed key count: {len(user_keys)}; service accounts checked: {len(accounts)}", "project service accounts")
        policy = self.g.json("projects", "get-iam-policy", self.project)
        bindings = policy.get("bindings", [])
        sa_admin = [(b.get("role"), m) for b in bindings
                    if b.get("role") in ("roles/iam.serviceAccountAdmin", "roles/iam.serviceAccountKeyAdmin")
                    for m in b.get("members", []) if m.startswith("serviceAccount:")]
        self.set("1.6", "FAIL" if sa_admin else "PASS", f"Direct project-level SA admin/key-admin grants to SA: {len(sa_admin)}", "direct project IAM only")
        sa_users = [b.get("role") for b in bindings if b.get("role") in
                    ("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator")
                    and b.get("members")]
        self.set("1.7", "FAIL" if sa_users else "PASS", f"Direct project-level Service Account User/Token Creator bindings: {len(sa_users)}", "direct project IAM only")

    def monitoring(self):
        metrics = self.g.json("logging", "metrics", "list")
        policies = self.g.json("monitoring", "policies", "list")
        try:
            channels = self.g.json("beta", "monitoring", "channels", "list")
            channel_names = {ch.get("name") for ch in channels if ch.get("enabled", True)}
            channel_err = None
        except Exception as e:
            channel_names = set()
            channel_err = str(e)
        by_name = {short_name(m.get("name", "")): m for m in metrics}
        for cid, metric_name in self.config["logging_metrics"].items():
            metric = by_name.get(metric_name)
            if not metric:
                self.set(cid, "FAIL", f"Missing log-based metric {metric_name}")
                continue
            if not metric.get("filter", "").strip():
                self.set(cid, "FAIL", f"Log-based metric {metric_name} has an empty filter")
                continue
            marker = "logging.googleapis.com/user/" + metric_name
            linked = []
            for pol in policies:
                if pol.get("enabled", True) is False:
                    continue
                for cond in pol.get("conditions", []):
                    threshold = cond.get("conditionThreshold", {})
                    flt = threshold.get("filter", "")
                    if marker in flt and pol.get("notificationChannels"):
                        linked.append(pol)
                        break
            if not linked:
                self.set(cid, "FAIL", f"Metric {metric_name} exists; no enabled threshold alert with notification channel")
                continue
            if channel_err:
                self.set(cid, "REVIEW", f"Linked alert found but notification channels could not be read: {channel_err[:150]}")
                continue
            valid = [p for p in linked if any(ch in channel_names for ch in p.get("notificationChannels", []))]
            if not valid:
                self.set(cid, "REVIEW", f"Linked alert for {metric_name} has no verified enabled channel")
            else:
                self.set(cid, "PASS", f"Metric + enabled alert + enabled notification channel ({metric_name}); configuration only", "project configuration; delivery not tested")

    def dns(self):
        nets = self.g.json("compute", "networks", "list")
        policies = self.g.json("dns", "policies", "list")
        missing = []
        for net in nets:
            ref = network_ref(net.get("selfLink", ""))
            if ref is None:
                raise ValueError("Network selfLink unavailable for " + net.get("name", "?"))
            logging = any(true(p.get("enableLogging")) and any(
                network_ref(n.get("networkUrl", "")) == ref for n in p.get("networks", [])
            ) for p in policies)
            if not logging:
                missing.append(net.get("name", "?"))
        status = "N/A" if not nets else ("FAIL" if missing else "PASS")
        self.set("2.13", status, f"VPCs: {len(nets)}; without enabled DNS query logging: {', '.join(missing) if missing else 'none'}")

    def asset(self):
        services = self.g.json("services", "list", "--enabled")
        names = {s.get("config", {}).get("name", s.get("name", "")) for s in services}
        enabled = "cloudasset.googleapis.com" in names
        self.set("2.14", "PASS" if enabled else "FAIL", "Cloud Asset Inventory API enabled" if enabled else "Cloud Asset Inventory API disabled")

    def firewall(self):
        rules = self.g.json("compute", "firewall-rules", "list")
        for cid, port in [("3.6", 22), ("3.7", 3389)]:
            bad = [r.get("name", "?") for r in rules
                   if not true(r.get("disabled")) and r.get("direction", "INGRESS") == "INGRESS"
                   and is_public(r) and permitted_port(r, port)]
            self.set(cid, "FAIL" if bad else "PASS",
                     f"Active public ingress TCP/{port}: {', '.join(bad) if bad else 'none'}",
                     "project VPC firewall rules; hierarchical policies excluded")

    def compute(self):
        vms = self.g.json("compute", "instances", "list")
        if not vms:
            for cid in ["4.3", "4.8", "4.9"]:
                self.set(cid, "N/A", "No VMs found")
            return
        project_info = self.g.json("compute", "project-info", "describe")
        pm = {x.get("key"): str(x.get("value", "")) for x in project_info.get("commonInstanceMetadata", {}).get("items", [])}
        weak43, weak48, weak49 = [], [], []
        for vm in vms:
            name = vm.get("name", "?")
            zone = short_name(vm.get("zone", ""))
            if not zone:
                raise ValueError("VM zone missing for " + name)
            info = self.g.json("compute", "instances", "describe", name, f"--zone={zone}")
            im = {x.get("key"): str(x.get("value", "")) for x in info.get("metadata", {}).get("items", [])}
            oslogin = im.get("enable-oslogin", pm.get("enable-oslogin", "")).strip().lower() == "true"
            blocked = im.get("block-project-ssh-keys", "").strip().lower() == "true"
            if not (oslogin or blocked):
                weak43.append(name)
            shield = info.get("shieldedInstanceConfig", {})
            if not true(shield.get("enableVtpm")) or not true(shield.get("enableIntegrityMonitoring")):
                weak48.append(name)
            for nic in info.get("networkInterfaces", []):
                if nic.get("accessConfigs") or nic.get("ipv6AccessConfigs"):
                    weak49.append(name)
                    break
        self.set("4.3", "FAIL" if weak43 else "PASS", f"VMs without block-project-ssh-keys or effective OS Login: {', '.join(weak43) if weak43 else 'none'}")
        self.set("4.8", "FAIL" if weak48 else "PASS", f"VMs missing Shielded vTPM or integrity monitoring: {', '.join(weak48) if weak48 else 'none'}; Secure Boot optional in CIS v5")
        self.set("4.9", "FAIL" if weak49 else "PASS", f"VMs with external IP access configuration: {', '.join(weak49) if weak49 else 'none'}")

    def storage(self):
        buckets = self.g.json("storage", "buckets", "list")
        if not buckets:
            self.set("5.1", "N/A", "No Cloud Storage buckets")
            self.set("5.2", "N/A", "No Cloud Storage buckets")
            return
        project_policy = self.g.json("projects", "get-iam-policy", self.project)
        project_public = public_bindings(project_policy)
        exposed, uncertain, nonuniform = [], [], []
        for b in buckets:
            name = short_name(b.get("name", "")).replace("gs://", "")
            if not name:
                raise ValueError("Storage bucket name missing")
            config = self.g.json("storage", "buckets", "describe", "gs://" + name, "--raw")
            iam = self.g.json("storage", "buckets", "get-iam-policy", "gs://" + name)
            uni = config.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled")
            public = public_bindings(iam)
            if public or project_public:
                exposed.append(name)
            if not true(uni):
                nonuniform.append(name)
                uncertain.append(name + " (ACLs not assessed)")
        if exposed:
            self.set("5.1", "FAIL", "Public bucket/project IAM binding detected: " + ", ".join(exposed))
        elif uncertain:
            self.set("5.1", "REVIEW", "; ".join(uncertain))
        else:
            self.set("5.1", "PASS", f"{len(buckets)} bucket(s); no public IAM binding in bucket or project; UBLA on", "bucket+project IAM only; org inheritance excluded")
        self.set("5.2", "FAIL" if nonuniform else "PASS", f"Buckets lacking uniform bucket-level access: {', '.join(nonuniform) if nonuniform else 'none'}")

    def execute(self) -> list[Result]:
        groups = [
            (["1.5", "1.6", "1.7"], self.iam),
            (["2.5", "2.6", "2.7", "2.8", "2.9", "2.10"], self.monitoring),
            (["2.13"], self.dns),
            (["2.14"], self.asset),
            (["3.6", "3.7"], self.firewall),
            (["4.3", "4.8", "4.9"], self.compute),
            (["5.1", "5.2"], self.storage),
        ]
        for cids, method in groups:
            selected = [cid for cid in cids if cid in self.config["controls"]]
            if selected:
                self.group(selected, method)
        for cid in self.config["controls"]:
            if cid not in self.results:
                self.set(cid, "ERROR", "No result returned by this auditor")
        rows = [self.results[cid] for cid in self.config["controls"]]
        self.save(rows)
        return rows

    def save(self, rows: list[Result]) -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        with (self.output / "results.csv").open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=["cis", "status", "detail", "scope"])
            writer.writeheader()
            writer.writerows([asdict(row) for row in rows])
        passes = [row for row in rows if row.status == "PASS"]
        with (self.output / "pass_only.csv").open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=["cis", "status", "detail", "scope"])
            writer.writeheader()
            writer.writerows([asdict(row) for row in passes])
        counts = {status: sum(row.status == status for row in rows) for status in ("PASS", "FAIL", "REVIEW", "N/A", "ERROR")}
        summary = {"project": self.project, "run_at_utc": datetime.now(timezone.utc).isoformat(),
                   "counts": counts, "total": len(rows), "scope": "Project settings; inherited policies not fully assessed"}
        (self.output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        report = ["# BÁO CÁO TỔNG HỢP TIÊU CHÍ CIS GCP ĐẠT (PASS)", "",
                  f"- Project: `{self.project}`", f"- Thời điểm UTC: {summary['run_at_utc']}",
                  f"- PASS: **{len(passes)}/{len(rows)}** tiêu chí đã kiểm tra", "",
                  "| CIS | Tiêu chí | Trạng thái | Minh chứng / Giới hạn |",
                  "|---|---|---|---|"]
        for r in passes:
            detail = (r.detail + ("; Scope: " + r.scope if r.scope != "project" else "")).replace("|", "/").replace("\n", " ")
            report.append(f"| {r.cis} | {CONTROLS.get(r.cis, r.cis)} | PASS | {detail} |")
        report.extend(["", "> Đây là danh sách PASS, không phải chứng nhận toàn bộ CIS Benchmark đã đạt.",
                       "> Kết quả đầy đủ, bao gồm FAIL/REVIEW/N/A/ERROR, được lưu riêng trong `results.csv`.",
                       "> Chưa kiểm chứng end-to-end sự kiện Logging, email alert và quyền kế thừa từ Organization."])
        (self.output / "PASS_ONLY_REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")
