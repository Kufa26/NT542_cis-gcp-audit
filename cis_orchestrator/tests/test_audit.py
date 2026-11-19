import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_engine import AuditEngine, network_ref, permitted_port, is_public


class FakeGCloud:
    def __init__(self, project):
        self.project = project
        self.calls = []
    def json(self, *args):
        self.calls.append(args)
        k = " ".join(args)
        if k == "iam service-accounts list":
            return [{"email": "default@demo-project.iam.gserviceaccount.com"}]
        if k.startswith("iam service-accounts keys list"):
            return []
        if k == "projects get-iam-policy demo-project":
            return {"bindings": []}
        if k == "logging metrics list":
            return [{"name": f"projects/demo-project/metrics/{n}", "filter": "protoPayload.methodName=\"method\""}
                    for n in ["cis_25_owner_change_count", "cis_26_audit_config_change_count", "cis_27_custom_role_change_count", "cis_28_firewall_change_count", "cis_29_route_change_count", "cis_210_network_change_count"]]
        if k == "monitoring policies list":
            names = ["cis_25_owner_change_count", "cis_26_audit_config_change_count", "cis_27_custom_role_change_count", "cis_28_firewall_change_count", "cis_29_route_change_count", "cis_210_network_change_count"]
            return [{"enabled": True, "notificationChannels": ["projects/demo-project/notificationChannels/123"],
                     "conditions": [{"conditionThreshold": {"filter": 'metric.type="logging.googleapis.com/user/'+name+'"'}}]}
                    for name in names]
        if k == "beta monitoring channels list":
            return [{"name": "projects/demo-project/notificationChannels/123", "enabled": True}]
        if k == "compute networks list":
            return [{"name": "nt542-vpc", "selfLink": "https://www.googleapis.com/compute/v1/projects/demo-project/global/networks/nt542-vpc"}]
        if k == "dns policies list":
            return [{"name": "demo-policy", "enableLogging": True, "networks": [
                {"networkUrl": "https://compute.googleapis.com/compute/v1/projects/demo-project/global/networks/nt542-vpc"}]}]
        if k == "services list --enabled":
            return [{"config": {"name": "cloudasset.googleapis.com"}}]
        if k == "compute firewall-rules list":
            return [{"name": "default-allow-ssh", "direction": "INGRESS", "disabled": True,
                     "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}]
        if k == "compute instances list":
            return [{"name": "nt542-iap-vm", "zone": "https://compute.googleapis.com/compute/v1/projects/demo-project/zones/us-central1-a"}]
        if k == "compute project-info describe":
            return {"commonInstanceMetadata": {"items": []}}
        if k.startswith("compute instances describe nt542-iap-vm"):
            return {"metadata": {"items": [{"key": "block-project-ssh-keys", "value": "TRUE"}]},
                    "shieldedInstanceConfig": {"enableVtpm": True, "enableIntegrityMonitoring": True},
                    "networkInterfaces": [{"networkIP": "10.10.0.2"}]}
        if k == "storage buckets list":
            return [{"name": "run-sources-demo-project-us-central1"}]
        if k.startswith("storage buckets describe"):
            return {"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}}
        if k.startswith("storage buckets get-iam-policy"):
            return {"bindings": []}
        raise AssertionError("Unknown mock gcloud command: " + k)


class TestAudit(unittest.TestCase):
    def setUp(self):
        config_file = Path(__file__).resolve().parents[1] / "config.json"
        self.config = json.loads(config_file.read_text())
        self.config["project_id"] = "demo-project"

    def test_full_pass_and_pass_only_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = AuditEngine(self.config, Path(tmp))
            engine.g = FakeGCloud("demo-project")
            rows = engine.execute()
            self.assertEqual(len(rows), 18)
            self.assertTrue(all(r.status == "PASS" for r in rows), rows)
            self.assertTrue((Path(tmp) / "PASS_ONLY_REPORT.md").exists())
            self.assertEqual(len((Path(tmp) / "results.csv").read_text(encoding="utf-8-sig").splitlines()), 19)

    def test_detects_ssh_public_range(self):
        rule = {"allowed": [{"IPProtocol": "tcp", "ports": ["20-23"]}],
                "sourceRanges": ["0.0.0.0/0"], "direction": "INGRESS"}
        self.assertTrue(is_public(rule))
        self.assertTrue(permitted_port(rule, 22))
        self.assertFalse(permitted_port(rule, 3389))

    def test_host_normalization(self):
        self.assertEqual(network_ref("https://www.googleapis.com/compute/v1/projects/x/global/networks/y"),
                         network_ref("https://compute.googleapis.com/compute/v1/projects/x/global/networks/y"))

    def test_no_false_pass_if_inventory_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = AuditEngine(self.config, Path(tmp))
            class Failing:
                def json(self, *args):
                    raise RuntimeError("PERMISSION_DENIED")
            engine.g = Failing()
            rows = engine.execute()
            self.assertTrue(all(r.status == "ERROR" for r in rows))
            self.assertEqual(len((Path(tmp) / "pass_only.csv").read_text(encoding="utf-8-sig").splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
