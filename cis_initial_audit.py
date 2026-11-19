import csv
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

PROJECT = 'project-2dcdd108-5e41-45e8-bed'
OUT = Path('before')
OUT.mkdir(exist_ok=True)
results = []

def fetch(label, command):
    cmd = ['gcloud', *command, '--project', PROJECT, '--format=json']
    proc = subprocess.run(cmd, capture_output=True, text=True)
    (OUT / f'{label}_command.txt').write_text(' '.join(cmd) + '\n' + proc.stderr, encoding='utf-8')
    if proc.returncode != 0:
        return None, proc.stderr.strip() or 'gcloud failed'
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, 'Invalid JSON returned by gcloud'
    (OUT / f'{label}.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    return data, None

def add(cis, status, detail):
    results.append({'cis': cis, 'status': status, 'detail': detail})

def failed(cis, error):
    add(cis, 'ERROR', error)

services, err = fetch('services', ['services', 'list', '--enabled'])
if err:
    failed('2.14', err)
else:
    names = {s.get('config', {}).get('name', s.get('name', '')) for s in services}
    add('2.14', 'PASS' if 'cloudasset.googleapis.com' in names else 'FAIL', 'Cloud Asset API enabled' if 'cloudasset.googleapis.com' in names else 'Cloud Asset API not enabled')

networks, err = fetch('networks', ['compute', 'networks', 'list'])
if err:
    failed('3.1', err)
else:
    defaults = [n.get('name', '') for n in networks if n.get('name') == 'default']
    add('3.1', 'FAIL' if defaults else 'PASS', 'default network exists' if defaults else 'No default network')

rules, err = fetch('firewalls', ['compute', 'firewall-rules', 'list'])

def exposes_port(rule, port):
    if rule.get('disabled', False) or rule.get('direction', 'INGRESS') != 'INGRESS':
        return False
    sources = rule.get('sourceRanges', [])
    if not sources and not rule.get('sourceTags') and not rule.get('sourceServiceAccounts'):
        sources = ['0.0.0.0/0']
    if not any(source in ('0.0.0.0/0', '::/0') for source in sources):
        return False
    for entry in rule.get('allowed', []):
        proto = str(entry.get('IPProtocol', '')).lower()
        if proto == 'all':
            return True
        if proto != 'tcp':
            continue
        ports = entry.get('ports', [])
        if not ports:
            return True
        for item in ports:
            bits = str(item).split('-')
            try:
                if len(bits) == 1 and int(bits[0]) == port:
                    return True
                if len(bits) == 2 and int(bits[0]) <= port <= int(bits[1]):
                    return True
            except ValueError:
                pass
    return False

for control, port in [('3.6', 22), ('3.7', 3389)]:
    if err:
        failed(control, err)
    else:
        names = [r.get('name', '?') for r in rules if exposes_port(r, port)]
        add(control, 'FAIL' if names else 'PASS', 'Public ingress: ' + ', '.join(names) if names else 'No matching public ingress in VPC firewall rules (hierarchical policies not checked)')

subnets, err = fetch('subnets', ['compute', 'networks', 'subnets', 'list'])
if err:
    failed('3.10', err)
else:
    disabled = [f"{s.get('name','?')}@{s.get('region','?').split('/')[-1]}" for s in subnets if s.get('enableFlowLogs') is not True]
    add('3.10', 'N/A' if not subnets else ('FAIL' if disabled else 'PASS'), 'Disabled Flow Logs: ' + ', '.join(disabled[:8]) + (f' ... ({len(disabled)} subnets)' if len(disabled)>8 else '') if disabled else ('All subnet Flow Logs enabled' if subnets else 'No subnets'))

instances, err = fetch('instances', ['compute', 'instances', 'list'])
if err:
    for control in ('4.8', '4.9'):
        failed(control, err)
else:
    if not instances:
        for control in ('4.8', '4.9'):
            add(control, 'N/A', 'No VM instances')
    else:
        public = []
        weak = []
        uncertain = []
        for vm in instances:
            name = vm.get('name', '?')
            for nic in vm.get('networkInterfaces', []):
                if nic.get('accessConfigs') or nic.get('ipv6AccessConfigs'):
                    public.append(name)
            shield = vm.get('shieldedInstanceConfig')
            if shield is None:
                uncertain.append(name)
            elif not (shield.get('enableVtpm') and shield.get('enableIntegrityMonitoring')):
                weak.append(name)
        add('4.9', 'FAIL' if public else 'PASS', 'External IP access configuration: ' + ', '.join(sorted(set(public))) if public else 'No external IP access configurations')
        add('4.8', 'FAIL' if weak else ('REVIEW' if uncertain else 'PASS'), ('Shielded VM weak: ' + ', '.join(weak)) if weak else ('Shielded VM configuration needs review: ' + ', '.join(uncertain) if uncertain else 'vTPM and integrity monitoring enabled'))

metadata, err = fetch('project_metadata', ['compute', 'project-info', 'describe'])
if err:
    failed('4.4', err)
else:
    items = {x.get('key'): str(x.get('value', '')).strip().lower() for x in metadata.get('commonInstanceMetadata', {}).get('items', [])}
    oslogin = items.get('enable-oslogin', '(missing)')
    add('4.4', 'PASS' if oslogin == 'true' else 'FAIL', f'Project metadata enable-oslogin={oslogin}; check VM overrides separately')

buckets, err = fetch('buckets', ['storage', 'buckets', 'list'])
if err:
    for control in ('5.1', '5.2'):
        failed(control, err)
elif not buckets:
    for control in ('5.1', '5.2'):
        add(control, 'N/A', 'No Cloud Storage buckets')
else:
    for control in ('5.1', '5.2'):
        add(control, 'REVIEW', 'Buckets exist; inspect bucket IAM and Uniform Bucket-Level Access individually')

with (OUT / 'results.csv').open('w', newline='', encoding='utf-8-sig') as f:
    writer = csv.DictWriter(f, fieldnames=['cis', 'status', 'detail'])
    writer.writeheader()
    writer.writerows(results)
summary = {'project_id': PROJECT, 'audited_at_utc': datetime.now(timezone.utc).isoformat(), 'results': results}
(OUT / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'PROJECT: {PROJECT}')
print('CIS   STATUS    DETAILS')
for x in results:
    print(f"{x['cis']:<5} {x['status']:<9} {x['detail']}")
print('\nEvidence: before/results.csv, before/summary.json, before/*.json')
