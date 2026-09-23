import json
from collections import defaultdict
from pathlib import Path
import sys

def generate_master_report(alerts, flows, pcap_name, engine='unknown'):
    out_path = f"{Path(pcap_name).stem}_MASTER_REPORT.md"

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# 🔒 PCAP SECURITY ANALYSIS - MASTER REPORT\n")
        f.write(f"**File**: {pcap_name} | **Generated**: Master View (All Roles)\n")
        f.write(f"**Detection Engine**: {engine}\n\n")
        f.write("---\n\n")

        # EXECUTIVE SUMMARY
        f.write("## 📊 EXECUTIVE SUMMARY\n\n")
        crit = sum(1 for a in alerts if a['severity'] >= 9)
        high = sum(1 for a in alerts if 7 <= a['severity'] < 9)
        med = sum(1 for a in alerts if 5 <= a['severity'] < 7)
        f.write(f"**Total Alerts**: {len(alerts)}\n\n")
        f.write(f"| Severity | Count | Status |\n|---|---|---|\n")
        f.write(f"| 🔴 CRITICAL (9) | {crit} | ESCALATE |\n")
        f.write(f"| 🟠 HIGH (7-8) | {high} | INVESTIGATE |\n")
        f.write(f"| 🟡 MEDIUM (5-6) | {med} | MONITOR |\n\n")

        # TOP STATISTICS
        f.write("## 📈 STATISTICS\n\n")
        by_type = defaultdict(int)
        by_mitre = defaultdict(int)
        for a in alerts:
            by_type[a['type']] += 1
            by_mitre[a['mitre']] += 1

        f.write("### Attack Types\n")
        f.write("| Type | Count |\n|---|---|\n")
        for etype, cnt in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            f.write(f"| {etype} | {cnt} |\n")

        f.write("\n### MITRE Techniques\n")
        f.write("| Technique | Count |\n|---|---|\n")
        for tech, cnt in sorted(by_mitre.items(), key=lambda x: x[1], reverse=True):
            f.write(f"| {tech} | {cnt} |\n")

        # THREAT ACTORS
        f.write("\n## 👥 THREAT ACTORS\n\n")
        attackers = defaultdict(int)
        for a in alerts:
            attackers[a['src']] += 1
        f.write("### Top Attackers\n")
        f.write("| Source IP | Alerts | Action |\n|---|---|---|\n")
        for ip, cnt in sorted(attackers.items(), key=lambda x: x[1], reverse=True):
            action = "🔴 BLOCK NOW" if cnt >= 5 else "🟡 MONITOR"
            f.write(f"| {ip} | {cnt} | {action} |\n")

        # VULNERABLE ASSETS
        f.write("\n## 🎯 VULNERABLE ASSETS\n\n")
        targets = defaultdict(int)
        for a in alerts:
            targets[a['dst']] += 1
        f.write("### Top Targets\n")
        f.write("| Target IP | Alerts | Action |\n|---|---|---|\n")
        for ip, cnt in sorted(targets.items(), key=lambda x: x[1], reverse=True):
            action = "🔴 PATCH NOW" if cnt >= 5 else "🟡 HARDEN"
            f.write(f"| {ip} | {cnt} | {action} |\n")

        # CRITICAL ALERTS - ALL ROLES VIEW
        f.write("\n## 🚨 CRITICAL & HIGH SEVERITY ALERTS\n\n")
        f.write("| Packet | Time | Src | Dst | Attack | MITRE | Severity | Blue Check | Fix |\n")
        f.write("|---|---|---|---|---|---|---|---|---|\n")
        for a in sorted(alerts, key=lambda x: x['severity'], reverse=True):
            if a['severity'] >= 7:
                f.write(f"| {a['pkt']} | {a['ts']} | {a['src']} | {a['dst']} | {a['type']} | {a['mitre']} | {a['severity']} | {a['blue']} | {a['fix']} |\n")

        # L1 SOC TRIAGE SECTION
        f.write("\n---\n\n")
        f.write("## 🟢 L1 SOC ANALYST VIEW\n\n")
        f.write("### Quick Decision Matrix\n")
        f.write("**Your Job**: Triage and escalate\n\n")
        f.write("| Alert Count | Your Action |\n|---|---|\n")
        f.write(f"| CRITICAL: {crit} | ⚡ ESCALATE TO L2 IMMEDIATELY |\n")
        f.write(f"| HIGH: {high} | 📞 CALL L2, GET APPROVAL |\n")
        f.write(f"| MEDIUM: {med} | ✅ LOG AND MONITOR |\n\n")
        f.write("### All Alerts for Triage\n")
        f.write("| Packet | Attacker | Target | Attack |\n|---|---|---|---|\n")
        for a in alerts:
            f.write(f"| {a['pkt']} | {a['src']} | {a['dst']} | {a['type']} |\n")

        # L2 INVESTIGATION SECTION
        f.write("\n---\n\n")
        f.write("## 🟠 L2 INVESTIGATION VIEW\n\n")
        f.write("### Investigation Tasks by Attack Type\n\n")
        by_type_grouped = defaultdict(list)
        for a in alerts:
            by_type_grouped[a['type']].append(a)

        for etype in sorted(by_type_grouped.keys()):
            alerts_list = by_type_grouped[etype]
            f.write(f"### {etype} ({len(alerts_list)} total)\n")
            f.write(f"**Where to look**: {alerts_list[0]['blue']}\n")
            f.write(f"**How to fix**: {alerts_list[0]['fix']}\n\n")
            f.write(f"**Affected packets**: {', '.join(str(a['pkt']) for a in alerts_list[:10])}")
            if len(alerts_list) > 10:
                f.write(f" ... +{len(alerts_list)-10} more\n\n")
            else:
                f.write("\n\n")

        # L3 THREAT HUNTING SECTION
        f.write("\n---\n\n")
        f.write("## 🔵 L3 THREAT HUNT VIEW\n\n")
        f.write("### Attack Timeline (Full)\n\n")
        by_time = sorted(alerts, key=lambda x: x['ts'])
        for a in by_time:
            severity_emoji = "🔴" if a['severity'] >= 9 else "🟠" if a['severity'] >= 7 else "🟡"
            f.write(f"{severity_emoji} **T+{a['ts']}s** | PKT-{a['pkt']}\n")
            f.write(f"  - **Attack**: {a['type']} | **MITRE**: {a['mitre']} | **Severity**: {a['severity']}\n")
            f.write(f"  - **Flow**: {a['src']} → {a['dst']}\n")
            f.write(f"  - **Validate**: {a['blue']}\n")
            f.write(f"  - **Remediate**: {a['fix']}\n\n")

        # PENTESTER EVIDENCE SECTION
        f.write("\n---\n\n")
        f.write("## 🔴 PENTESTER EVIDENCE\n\n")
        f.write("### Exploitations by Severity (Copy into Report)\n\n")
        severity_groups = defaultdict(list)
        for a in alerts:
            severity_groups[a['severity']].append(a)

        for sev in sorted(severity_groups.keys(), reverse=True):
            f.write(f"### Severity {sev}\n\n")
            for a in severity_groups[sev]:
                f.write(f"- **{a['type']}** (MITRE: {a['mitre']})\n")
                f.write(f"  - Source: {a['src']}\n")
                f.write(f"  - Target: {a['dst']}\n")
                f.write(f"  - Packet: {a['pkt']}\n")
                f.write(f"  - Evidence: Found in packet #{a['pkt']} (timestamp {a['ts']})\n\n")

        # BLUE TEAM SECTION
        f.write("\n---\n\n")
        f.write("## 🛡️ BLUE TEAM - DETECTION GAPS\n\n")
        f.write("### Coverage Analysis\n\n")
        f.write("| Attack Type | Count | Detection Source | Coverage Status |\n")
        f.write("|---|---|---|---|\n")
        coverage = defaultdict(lambda: {'count': 0})
        for a in alerts:
            coverage[a['type']]['count'] += 1
            coverage[a['type']]['blue'] = a['blue']
            coverage[a['type']]['fix'] = a['fix']

        for etype in sorted(coverage.keys()):
            stats = coverage[etype]
            status = "✅ COVERED" if stats['count'] <= 1 else "⚠️ GAPS"
            f.write(f"| {etype} | {stats['count']} | {stats['blue']} | {status} |\n")

        f.write("\n### Detection Rules to Implement\n\n")
        for etype in sorted(coverage.keys()):
            stats = coverage[etype]
            f.write(f"**{etype}**\n")
            f.write(f"- Monitor: {stats['blue']}\n")
            f.write(f"- Action: {stats['fix']}\n\n")

        # PURPLE TEAM SECTION
        f.write("\n---\n\n")
        f.write("## 🟣 PURPLE TEAM - COVERAGE MAP\n\n")
        f.write("### Red Capabilities vs Blue Detection\n\n")
        f.write("| Technique | MITRE | Red Found | Blue Logs | Status |\n")
        f.write("|---|---|---|---|---|\n")
        techniques = set()
        for a in alerts:
            techniques.add((a['type'], a['mitre'], a['blue']))
        for etype, mitre, blue_source in sorted(techniques):
            status = "✅ DETECTED" if blue_source else "❌ BLIND SPOT"
            f.write(f"| {etype} | {mitre} | ✅ Yes | {blue_source} | {status} |\n")

        # NETWORK TEAM SECTION
        f.write("\n---\n\n")
        f.write("## 🌐 NETWORK DETECTION TEAM VIEW\n\n")
        f.write("### Network-Based Indicators\n\n")
        f.write("### Suspicious Flows\n")
        f.write("| Source | Destination | Packets | Bytes | Threat Level |\n")
        f.write("|---|---|---|---|---|\n")
        for flow, stats in sorted(flows.items(), key=lambda x: x[1]['bytes'], reverse=True)[:15]:
            src, dst = flow.split('-')
            threat = "🔴 BLOCK" if stats['bytes'] > 100000 else "🟠 INSPECT" if stats['bytes'] > 10000 else "🟡 MONITOR"
            f.write(f"| {src} | {dst} | {stats['pkts']} | {stats['bytes']} | {threat} |\n")

        # SUMMARY RECOMMENDATIONS
        f.write("\n---\n\n")
        f.write("## ✅ ACTION ITEMS (ALL TEAMS)\n\n")
        f.write("### Immediate (0-1 hour)\n")
        f.write(f"- [ ] L1: Triage {crit} CRITICAL alerts\n")
        f.write(f"- [ ] L2: Investigate top 5 HIGH severity findings\n")
        f.write(f"- [ ] Network: Block top {min(5, len(attackers))} attacker IPs\n")
        f.write(f"- [ ] Blue: Search logs for validation\n\n")

        f.write("### Short-term (1-24 hours)\n")
        f.write(f"- [ ] L3: Full timeline analysis & root cause\n")
        f.write(f"- [ ] Patch: Harden top {min(5, len(targets))} target IPs\n")
        f.write(f"- [ ] Blue: Implement detection rules for gaps\n")
        f.write(f"- [ ] Purple: Update playbook with findings\n\n")

        f.write("### Follow-up (24+ hours)\n")
        f.write("- [ ] Incident response review\n")
        f.write("- [ ] Security awareness training (if user compromise)\n")
        f.write("- [ ] Penetration test follow-up (if pentest)\n")
        f.write("- [ ] Update threat intelligence feeds\n\n")

        f.write("---\n\n")
        f.write(f"**Report Generated**: {Path(pcap_name).stem}_MASTER_REPORT.md\n")
        f.write("**Audience**: All Security Teams (L1, L2, L3, Pentesters, Blue, Purple, Network)\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python master_report.py <pcap_file> [--alerts-json]")
        sys.exit(1)

    pcap = sys.argv[1]
    alerts_json = sys.argv[2] if len(sys.argv) > 2 else f"{Path(pcap).stem}_analysis.json"

    if not Path(alerts_json).exists():
        print(f"[ERROR] Generate alerts first: python enhanced_detector.py {pcap}")
        sys.exit(1)

    try:
        with open(alerts_json, encoding='utf-8') as f:
            data = json.load(f)
        generate_master_report(data['alerts'], data['flows'], pcap, data.get('engine', 'unknown'))
        print(f"[OK] Master report: {Path(pcap).stem}_MASTER_REPORT.md")
    except Exception as e:
        print(f"[ERROR] Master report failed: {e}")
        sys.exit(1)
