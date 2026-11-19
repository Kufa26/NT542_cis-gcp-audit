NT542 - CIS GCP Benchmark v5.0.0: 5 Logging Controls (2.5, 2.6, 2.7, 2.9, 2.10)

Purpose: Ansible checks existing Log-based Metrics and Monitoring Alert Policies.
If approved, it creates missing metrics and linked alert policies, using the existing
email notification channel. It DOES NOT modify firewall, routes, IAM, or VM resources.

Requirements:
  - gcloud logged in, current project project-2dcdd108-5e41-45e8-bed
  - ansible-playbook installed on Cloud Shell / Linux / WSL2
  - Email notification channel exists: .../7993635890019693006
  - Owner's permission to create metrics and alert policies in the shared project

1) Extract ZIP inside ~/cis-gcp-audit.
2) Preview file and check current Project and channel.
3) Dry run (read only):
   ansible-playbook -i localhost, -c local remediate_logging_5.yml --syntax-check
   ansible-playbook -i localhost, -c local remediate_logging_5.yml -e approve_change=false
4) After explicit project-owner approval, apply:
   set -o pipefail
   ansible-playbook -i localhost, -c local remediate_logging_5.yml -e approve_change=true | tee ansible_logging_5.log
5) Verify:
   gcloud logging metrics list --format="table(name,filter)"
   gcloud monitoring policies list --format="table(displayName,enabled)"
   python3 audit_logging_monitoring.py --project project-2dcdd108-5e41-45e8-bed --output report/logging-after-five

Important:
- Each metric and alert has a distinct name. Repeated runs skip matching names.
- Name-based idempotence does not verify correctness of pre-existing named resources.
- This prototype tests intended resource types "global". If the API returns an
  unsupported resource-type error, stop and inspect that metric's real data model.
- CIS Audit may still say REVIEW: the Python checker conservatively requires
  human inspection of Boolean expressions, threshold, email channel, and delivery.
- Log metrics and alerts can result in charges; verify project billing budget.
- Do not modify project IAM/firewall/routes just to generate test notifications.
