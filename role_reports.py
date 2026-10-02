import json
import sys
from collections import defaultdict
from pathlib import Path

ROLES = {
    'L1': 'L1 SOC Triage',
    'L2': 'L2 Investigation',
    'L3': 'L3 Threat Hunt',
    'pentester': 'Pentest Evidence',
    'blue': 'Blue Team Detection Gaps',
    'purple': 'Purple Team Coverage',
    'network': 'Network Detection Analysis',
}

def generate_role_reports(alerts, flows, pcap_name):
    type_info = {}
    for a in alerts:
        type_info.setdefault(a['type'], {'mitre': a['mitre'], 'blue': a['blue'], 'fix': a['fix']})

    for role, title in ROLES.items():
        out_path = f"{Path(pcap_name).stem}_{role}_report.md"

        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(f"# {title}\n")
            f.write(f"**File**: {pcap_name} | **Role**: {role.upper()}\n\n")

            if role == 'L1':
                f.write("## Quick Triage\n")
                f.write(f"**Total Alerts**: {len(alerts)}\n\n")
                crit = sum(1 for a in alerts if a['severity'] >= 9)
                high = sum(1 for a in alerts if 7 <= a['severity'] < 9)
                f.write(f"CRITICAL: {crit} | HIGH: {high}\n\n")
                f.write("| Packet | Time | Attacker | Target | Attack Type |\n|---|---|---|---|---|\n")
                for a in alerts:
                    f.write(f"| {a['pkt']} | {a['ts']} | {a['src']} | {a['dst']} | {a['type']} |\n")
                f.write("\n**Action**: Escalate CRITICAL/HIGH to L2 analyst\n")

            elif role == 'L2':
                f.write("## Investigation Tasks\n")
                by_type = defaultdict(list)
                for a in alerts:
                    by_type[a['type']].append(a)

                for etype, alerts_list in sorted(by_type.items()):
                    f.write(f"\n### {etype} ({len(alerts_list)} alerts)\n")
                    for a in alerts_list[:3]:
                        f.write(f"- **PKT-{a['pkt']}**: {a['src']} -> {a['dst']}\n")
                        f.write(f"  Check: {a['blue']}\n")
                    if len(alerts_list) > 3:
                        f.write(f"- ... +{len(alerts_list)-3} more\n")
                f.write("\n**Action**: Search logs listed above, correlate with alerts\n")

            elif role == 'L3':
                f.write("## Advanced Analysis & Hunting\n")
                unique_attacks = set(a['type'] for a in alerts)
                unique_ips_src = set(a['src'] for a in alerts)
                unique_ips_dst = set(a['dst'] for a in alerts)

                f.write(f"**Unique Attack Types**: {len(unique_attacks)}\n")
                f.write(f"**Unique Source IPs**: {len(unique_ips_src)}\n")
                f.write(f"**Unique Target IPs**: {len(unique_ips_dst)}\n\n")

                f.write("### Attack Timeline\n")
                for a in sorted(alerts, key=lambda x: x['ts']):
                    f.write(f"- **T+{a['ts']}s**: {a['type']} ({a['mitre']}) - {a['src']} -> {a['dst']}\n")
                    f.write(f"  Validate: {a['blue']} | Fix: {a['fix']}\n")

            elif role == 'pentester':
                f.write("## Engagement Evidence\n")
                severity_groups = defaultdict(list)
                for a in alerts:
                    severity_groups[a['severity']].append(a)

                for sev in sorted(severity_groups.keys(), reverse=True):
                    f.write(f"\n### Severity {sev}\n")
                    for a in severity_groups[sev][:5]:
                        f.write(f"- **{a['type']}** (MITRE: {a['mitre']})\n")
                        f.write(f"  Source: {a['src']} -> Target: {a['dst']}\n")
                        f.write(f"  Packet #: {a['pkt']}\n")
                f.write("\n**Report use**: Include in pentest report under 'Findings' section\n")

            elif role == 'blue':
                f.write("## Detection Gaps & Coverage\n")
                coverage = defaultdict(lambda: {'detected': 0, 'total': 0})
                for a in alerts:
                    coverage[a['type']]['total'] += 1
                    if a['severity'] >= 7:
                        coverage[a['type']]['detected'] += 1

                f.write("| Attack Type | Detection Rate | Validation Source | Remediation |\n|---|---|---|---|\n")
                for etype in sorted(coverage.keys()):
                    stats = coverage[etype]
                    rate = (stats['detected'] / stats['total'] * 100) if stats['total'] > 0 else 0
                    info = type_info[etype]
                    f.write(f"| {etype} | {rate:.0f}% ({stats['detected']}/{stats['total']}) | {info['blue']} | {info['fix']} |\n")
                f.write("\n**Action**: Implement detection rules in SIEM/IDS for gaps\n")

            elif role == 'purple':
                f.write("## Red vs Blue Coverage Map\n")
                f.write("| Technique | MITRE ID | Red Found | Blue Logs | Status |\n|---|---|---|---|---|\n")
                for etype in sorted(type_info.keys()):
                    info = type_info[etype]
                    status = "Detected" if info['blue'] else "Blind Spot"
                    f.write(f"| {etype} | {info['mitre']} | Yes | {info['blue']} | {status} |\n")
                f.write("\n**Use**: Update purple team playbook with findings\n")

            elif role == 'network':
                f.write("## Network Behavior Analysis\n")
                f.write("### Top Attackers\n")
                attackers = defaultdict(int)
                for a in alerts:
                    attackers[a['src']] += 1
                for ip, cnt in sorted(attackers.items(), key=lambda x: x[1], reverse=True)[:5]:
                    f.write(f"- {ip}: {cnt} alerts (Block immediately)\n")

                f.write("\n### Top Targets\n")
                targets = defaultdict(int)
                for a in alerts:
                    targets[a['dst']] += 1
                for ip, cnt in sorted(targets.items(), key=lambda x: x[1], reverse=True)[:5]:
                    f.write(f"- {ip}: {cnt} alerts (Harden immediately)\n")

                f.write("\n### Flows (Top 5)\n")
                f.write("| Source -> Destination | Attacks |\n|---|---|\n")
                flow_attacks = defaultdict(int)
                for a in alerts:
                    flow_attacks[f"{a['src']} -> {a['dst']}"] += 1
                for flow, cnt in sorted(flow_attacks.items(), key=lambda x: x[1], reverse=True)[:5]:
                    f.write(f"| {flow} | {cnt} |\n")

        print(f"[OK] {role.upper()}: {out_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python role_reports.py <pcap_file> [alerts_json]")
        sys.exit(1)

    pcap = sys.argv[1]
    alerts_json = sys.argv[2] if len(sys.argv) > 2 else f"{Path(pcap).stem}_analysis.json"

    if not Path(alerts_json).exists():
        print(f"[ERROR] Generate alerts first: python enhanced_detector.py {pcap} --json")
        sys.exit(1)

    try:
        with open(alerts_json, encoding='utf-8') as f:
            data = json.load(f)
        generate_role_reports(data['alerts'], data['flows'], pcap)
    except Exception as e:
        print(f"[ERROR] Role reports failed: {e}")
        sys.exit(1)
