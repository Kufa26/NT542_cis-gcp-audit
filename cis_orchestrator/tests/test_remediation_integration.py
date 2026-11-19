"""Simulated orchestration tests; never call gcloud or Ansible."""
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main as app
from audit_engine import Result


class FakeAnsibleProcess:
    def __init__(self, *args, **kwargs):
        self.stdout = iter(["PLAY [mock]\n", "changed: [localhost]\n"])
    def wait(self):
        return 0


class TestRemediationIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "remediate_dns_213.yml").write_text("---\n- hosts: localhost\n  tasks: []\n")
        self.config = {
            "project_id": "demo-project",
            "playbooks": {"2.13": "remediate_dns_213.yml"},
        }
        self.base = self.root / "run"
        self.base.mkdir()
        self.args = SimpleNamespace(control="2.13", apply=True, reason="Approved simulated lab change")
        self.approval = "APPLY 2.13 demo-project"

    def test_fail_to_pass_flow(self):
        statuses = ["FAIL", "PASS"]
        labels = []
        def fake_audit(config, root, label):
            labels.append(label)
            return [Result("2.13", statuses.pop(0), "Mock result")]

        with patch.object(app, "HERE", self.root), \
             patch.object(app, "audit", side_effect=fake_audit), \
             patch.object(app.shutil, "which", return_value="/mock/ansible"), \
             patch.object(app.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="syntax ok", stderr="")) as syntax, \
             patch.object(app.subprocess, "Popen", side_effect=FakeAnsibleProcess) as ansible, \
             patch("builtins.input", return_value=self.approval):
            code = app.guarded_remediation(self.args, self.config, self.base)

        self.assertEqual(code, 0)
        self.assertEqual(labels, ["before_apply", "after_apply"])
        syntax.assert_called_once()
        ansible.assert_called_once()
        self.assertTrue((self.base / "ansible_remediation.log").exists())
        self.assertTrue((self.base / "change_reason.txt").exists())

    def test_pass_control_does_not_run_ansible(self):
        with patch.object(app, "HERE", self.root), \
             patch.object(app, "audit", return_value=[Result("2.13", "PASS", "Already secure")]), \
             patch("builtins.input", return_value=self.approval), \
             patch.object(app.shutil, "which", return_value="/mock/ansible"), \
             patch.object(app.subprocess, "run") as syntax, \
             patch.object(app.subprocess, "Popen") as ansible:
            code = app.guarded_remediation(self.args, self.config, self.base)

        self.assertEqual(code, 2)
        syntax.assert_not_called()
        ansible.assert_not_called()

    def test_no_approval_means_no_changes(self):
        with patch.object(app, "HERE", self.root), \
             patch("builtins.input", return_value="NO"), \
             patch.object(app.shutil, "which", return_value="/mock/ansible"), \
             patch.object(app, "audit") as do_audit, \
             patch.object(app.subprocess, "Popen") as ansible:
            code = app.guarded_remediation(self.args, self.config, self.base)

        self.assertEqual(code, 2)
        do_audit.assert_not_called()
        ansible.assert_not_called()

    def test_remains_fail_after_ansible_needs_review(self):
        with patch.object(app, "HERE", self.root), \
             patch.object(app, "audit", return_value=[Result("2.13", "FAIL", "Still broken")]) as do_audit, \
             patch.object(app.shutil, "which", return_value="/mock/ansible"), \
             patch.object(app.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="syntax ok", stderr="")), \
             patch.object(app.subprocess, "Popen", side_effect=FakeAnsibleProcess), \
             patch("builtins.input", return_value=self.approval):
            code = app.guarded_remediation(self.args, self.config, self.base)

        self.assertEqual(code, 1)
        self.assertEqual(do_audit.call_count, 2)


if __name__ == "__main__":
    unittest.main()
