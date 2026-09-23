import struct
import socket
import re
import json
import csv
import sys
import os
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from datetime import datetime

HTTP_SCOPE_TYPES = {'SQLi', 'XSS', 'XXE', 'PathTraversal'}
DNS_SCOPE_TYPES = {'DNS Tunnel'}
BINARY_SCOPE_TYPES = {'BufferOverflow'}

TSHARK_FIELDS = [
    'frame.number', 'frame.time_epoch', 'frame.len',
    'ip.src', 'ip.dst',
    'tcp.srcport', 'tcp.dstport', 'tcp.flags.syn', 'tcp.flags.ack',
    'udp.srcport', 'udp.dstport',
    'http.request.method', 'http.request.uri', 'http.request.line', 'http.file_data',
    'dns.qry.name',
    'tcp.payload', 'udp.payload',
]

def find_tshark():
    env_path = os.environ.get('TSHARK_PATH')
    if env_path and Path(env_path).exists():
        return env_path
    found = shutil.which('tshark') or shutil.which('tshark.exe')
    if found:
        return found
    for candidate in (
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ):
        if Path(candidate).exists():
            return candidate
    return None

def _is_texty(b, threshold=0.6):
    if not b:
        return False
    printable = sum(1 for c in b if 32 <= c <= 126 or c in (9, 10, 13))
    return (printable / len(b)) >= threshold

def _hexfield_to_bytes(val):
    if not val:
        return b''
    try:
        return bytes.fromhex(val.replace(':', ''))
    except ValueError:
        return b''

SEVERITY_MAP = {
    'SQLi': 9, 'RCE': 9, 'XXE': 8, 'CmdInj': 9, 'XSS': 6, 'PathTraversal': 7, 'LDAP': 7,
    'SYN Scan': 5, 'Kerberos': 8, 'Bloodhound': 7, 'NMAP': 4, 'DDOS': 9, 'Exfiltration': 8,
    'Lateral Movement': 8, 'DNS Tunnel': 7, 'SSH Brute': 7, 'Credential Dumping': 9,
    'BufferOverflow': 9
}

SIGNATURES = {
    'SQLi': [
        {'pattern': rb"union.*select", 'mitre_id': 'T1190', 'blue_source': 'WAF logs, DB query logs', 'remediation': 'Use parameterized queries, input validation'},
        {'pattern': rb"union\s+all\s+select", 'mitre_id': 'T1190', 'blue_source': 'WAF logs, DB query logs', 'remediation': 'Input validation, query logging'},
        {'pattern': rb"or\s+1\s*=\s*1", 'mitre_id': 'T1190', 'blue_source': 'Application logs, SQL audit trail', 'remediation': 'Implement ORM/prepared statements'},
        {'pattern': rb"or\s+1\s*=\s*'1", 'mitre_id': 'T1190', 'blue_source': 'SQL audit trail', 'remediation': 'Parameterized queries'},
        {'pattern': rb"';.*--", 'mitre_id': 'T1190', 'blue_source': 'Database audit log', 'remediation': 'Sanitize comment syntax, use escaping'},
        {'pattern': rb"';\s*drop", 'mitre_id': 'T1190', 'blue_source': 'Database audit log', 'remediation': 'Query whitelisting, parameterization'},
        {'pattern': rb"xp_cmdshell", 'mitre_id': 'T1190', 'blue_source': 'SQL Server logs, Windows event log', 'remediation': 'Disable xp_cmdshell, use MSSQL hardening'},
        {'pattern': rb"sp_oacreate", 'mitre_id': 'T1190', 'blue_source': 'SQL Server audit', 'remediation': 'Disable OLE procedures'},
        {'pattern': rb"exec\s+sp_", 'mitre_id': 'T1190', 'blue_source': 'DB logs', 'remediation': 'Restrict stored procedure execution'},
        {'pattern': rb"sleep\s*\(\s*\d+\s*\)", 'mitre_id': 'T1190', 'blue_source': 'Query execution time logs, IDS/IPS', 'remediation': 'Query timeout enforcement, rate limiting'},
        {'pattern': rb"benchmark\s*\(", 'mitre_id': 'T1190', 'blue_source': 'MySQL logs', 'remediation': 'Query timeout limits'},
        {'pattern': rb"waitfor\s+delay", 'mitre_id': 'T1190', 'blue_source': 'SQL Server logs', 'remediation': 'Query timeout enforcement'},
        {'pattern': rb"cast\s*\(\s*", 'mitre_id': 'T1190', 'blue_source': 'DB logs', 'remediation': 'Query validation'},
        {'pattern': rb"convert\s*\(\s*", 'mitre_id': 'T1190', 'blue_source': 'DB logs', 'remediation': 'Type checking in queries'},
        {'pattern': rb"from\s+information_schema", 'mitre_id': 'T1190', 'blue_source': 'DB audit', 'remediation': 'Restrict schema access'},
        {'pattern': rb"load_file\s*\(", 'mitre_id': 'T1190', 'blue_source': 'File access logs', 'remediation': 'Disable file functions'},
        {'pattern': rb"into\s+outfile", 'mitre_id': 'T1190', 'blue_source': 'File access logs, DB audit', 'remediation': 'Disable file write functions'},
        {'pattern': rb"into\s+dumpfile", 'mitre_id': 'T1190', 'blue_source': 'File access logs', 'remediation': 'Disable file operations'},
    ],
    'RCE': [
        {'pattern': rb"bash\s+-i", 'mitre_id': 'T1059', 'blue_source': 'Process logs, shell history, EDR', 'remediation': 'Disable bash reverse shells, use AppArmor'},
        {'pattern': rb"/bin/bash", 'mitre_id': 'T1059', 'blue_source': 'Process logs, EDR', 'remediation': 'Restrict bash execution'},
        {'pattern': rb"/bin/sh", 'mitre_id': 'T1059', 'blue_source': 'Process logs, auditd', 'remediation': 'AppArmor/SELinux profiles'},
        {'pattern': rb"cmd\.exe", 'mitre_id': 'T1059', 'blue_source': 'Windows Event Log 4688, Sysmon', 'remediation': 'Restrict cmd.exe, enable Script Block Logging'},
        {'pattern': rb"powershell", 'mitre_id': 'T1059', 'blue_source': 'PowerShell audit log, Windows Defender', 'remediation': 'Constrained language mode, disable PS v2'},
        {'pattern': rb"powershell\.exe", 'mitre_id': 'T1059', 'blue_source': 'Windows logs, Sysmon', 'remediation': 'Disable PS execution'},
        {'pattern': rb"pwsh", 'mitre_id': 'T1059', 'blue_source': 'Process logs', 'remediation': 'Restrict PowerShell Core'},
        {'pattern': rb"eval\s*\(", 'mitre_id': 'T1059', 'blue_source': 'Application logs, WAF logs', 'remediation': 'Disable eval(), use AST parsing'},
        {'pattern': rb"exec\s*\(", 'mitre_id': 'T1059', 'blue_source': 'Python/PHP logs', 'remediation': 'Disable exec()'},
        {'pattern': rb"system\s*\(", 'mitre_id': 'T1059', 'blue_source': 'Application logs', 'remediation': 'Use safe subprocess calls'},
        {'pattern': rb"passthru\s*\(", 'mitre_id': 'T1059', 'blue_source': 'PHP logs', 'remediation': 'Disable dangerous functions'},
        {'pattern': rb"shell_exec", 'mitre_id': 'T1059', 'blue_source': 'PHP logs', 'remediation': 'Disable shell_exec()'},
        {'pattern': rb"proc_open", 'mitre_id': 'T1059', 'blue_source': 'PHP logs', 'remediation': 'Restrict process functions'},
        {'pattern': rb"backtick\s+`", 'mitre_id': 'T1059', 'blue_source': 'Shell logs', 'remediation': 'Disable command substitution'},
        {'pattern': rb"\$\(\s*", 'mitre_id': 'T1059', 'blue_source': 'Shell logs', 'remediation': 'Disable variable expansion'},
        {'pattern': rb"nc\s+-l", 'mitre_id': 'T1059', 'blue_source': 'Network logs, process logs', 'remediation': 'Restrict netcat, block reverse shells'},
        {'pattern': rb"ncat", 'mitre_id': 'T1059', 'blue_source': 'Network logs', 'remediation': 'Block ncat'},
    ],
    'CmdInj': [
        {'pattern': rb";\s*cat\s+/", 'mitre_id': 'T1059', 'blue_source': 'Process execution logs, auditd', 'remediation': 'Input validation, shell escape functions'},
        {'pattern': rb"\|\s*cat\s+", 'mitre_id': 'T1059', 'blue_source': 'Process logs', 'remediation': 'Disable shell operators'},
        {'pattern': rb"`cat\s+", 'mitre_id': 'T1059', 'blue_source': 'Shell logs', 'remediation': 'Disable backtick substitution'},
        {'pattern': rb"\$\(\s*cat", 'mitre_id': 'T1059', 'blue_source': 'Shell logs', 'remediation': 'Disable variable expansion'},
        {'pattern': rb"&&\s*whoami", 'mitre_id': 'T1033', 'blue_source': 'Process logs, auditd, command history', 'remediation': 'Whitelist commands, disable shell operators'},
        {'pattern': rb"\|\s*whoami", 'mitre_id': 'T1033', 'blue_source': 'Process logs', 'remediation': 'Restrict piping'},
        {'pattern': rb";\s*id\s*;", 'mitre_id': 'T1033', 'blue_source': 'Process logs', 'remediation': 'Command whitelisting'},
        {'pattern': rb";\s*ls\s+-", 'mitre_id': 'T1526', 'blue_source': 'Process logs', 'remediation': 'Restrict directory listing'},
        {'pattern': rb">\s*/tmp/", 'mitre_id': 'T1020', 'blue_source': 'File access logs', 'remediation': 'Restrict temp file writes'},
        {'pattern': rb"\|\s*nc\s+", 'mitre_id': 'T1095', 'blue_source': 'Network logs', 'remediation': 'Block shell pipes to network tools'},
    ],
    'XXE': [
        {'pattern': rb"<!ENTITY", 'mitre_id': 'T1083', 'blue_source': 'WAF logs, XML parser logs', 'remediation': 'Disable DTD processing, use safe XML libs'},
        {'pattern': rb"<!DOCTYPE", 'mitre_id': 'T1083', 'blue_source': 'WAF logs', 'remediation': 'Disable DOCTYPE declarations'},
        {'pattern': rb"SYSTEM\s+[\"']file://", 'mitre_id': 'T1083', 'blue_source': 'Network access logs, file access logs', 'remediation': 'Disable external entities, restrict file access'},
        {'pattern': rb"ENTITY\s+.*SYSTEM", 'mitre_id': 'T1083', 'blue_source': 'WAF logs', 'remediation': 'XML external entity prevention'},
        {'pattern': rb"php://filter", 'mitre_id': 'T1083', 'blue_source': 'PHP logs', 'remediation': 'Disable PHP wrappers'},
        {'pattern': rb"expect://", 'mitre_id': 'T1083', 'blue_source': 'PHP logs', 'remediation': 'Disable expect wrapper'},
        {'pattern': rb"file:///etc/", 'mitre_id': 'T1083', 'blue_source': 'File access logs', 'remediation': 'Restrict file URIs'},
        {'pattern': rb"jar:", 'mitre_id': 'T1083', 'blue_source': 'Java logs', 'remediation': 'Disable jar protocol'},
    ],
    'XSS': [
        {'pattern': rb"<script[^>]*>", 'mitre_id': 'T1602', 'blue_source': 'WAF logs, browser logs', 'remediation': 'CSP headers, output encoding'},
        {'pattern': rb"<svg.*onload", 'mitre_id': 'T1602', 'blue_source': 'WAF logs', 'remediation': 'SVG sanitization'},
        {'pattern': rb"javascript:", 'mitre_id': 'T1602', 'blue_source': 'WAF logs', 'remediation': 'Disable javascript: protocol'},
        {'pattern': rb"onerror\s*=", 'mitre_id': 'T1602', 'blue_source': 'DOM events, browser console', 'remediation': 'Input/output validation, Content-Security-Policy'},
        {'pattern': rb"onload\s*=", 'mitre_id': 'T1602', 'blue_source': 'Browser logs', 'remediation': 'Event handler filtering'},
        {'pattern': rb"onclick\s*=", 'mitre_id': 'T1602', 'blue_source': 'Browser logs', 'remediation': 'Event handler validation'},
        {'pattern': rb"onmouseover\s*=", 'mitre_id': 'T1602', 'blue_source': 'Browser logs', 'remediation': 'Mouse event filtering'},
        {'pattern': rb"<img[^>]*src\s*=", 'mitre_id': 'T1602', 'blue_source': 'WAF logs', 'remediation': 'Image source validation'},
        {'pattern': rb"<iframe[^>]*src\s*=", 'mitre_id': 'T1602', 'blue_source': 'WAF logs', 'remediation': 'Frame source validation'},
        {'pattern': rb"<link[^>]*href", 'mitre_id': 'T1602', 'blue_source': 'WAF logs', 'remediation': 'Link validation'},
    ],
    'PathTraversal': [
        {'pattern': rb"\.\./\.\./", 'mitre_id': 'T1526', 'blue_source': 'Web server logs, file access logs', 'remediation': 'Path canonicalization, strict directory limits'},
        {'pattern': rb"\.\.\x5c\.\.\x5c", 'mitre_id': 'T1526', 'blue_source': 'Windows logs', 'remediation': 'Backslash filtering'},
        {'pattern': rb"%2e%2e/", 'mitre_id': 'T1526', 'blue_source': 'WAF logs', 'remediation': 'URL decoding validation'},
        {'pattern': rb"..%5c", 'mitre_id': 'T1526', 'blue_source': 'Web logs', 'remediation': 'Double encoding detection'},
        {'pattern': rb"/etc/passwd", 'mitre_id': 'T1526', 'blue_source': 'File access audit, Sysmon', 'remediation': 'File permission checks, read ACLs'},
        {'pattern': rb"/etc/shadow", 'mitre_id': 'T1526', 'blue_source': 'File access audit', 'remediation': 'Restrict shadow file access'},
        {'pattern': rb"c:\\windows\\", 'mitre_id': 'T1526', 'blue_source': 'Windows logs', 'remediation': 'Windows system path protection'},
        {'pattern': rb"/etc/hosts", 'mitre_id': 'T1526', 'blue_source': 'File access logs', 'remediation': 'Restrict system file access'},
        {'pattern': rb"\.\.\\\.\.\\", 'mitre_id': 'T1526', 'blue_source': 'Windows logs', 'remediation': 'Path validation'},
    ],
    'LDAP': [
        {'pattern': rb"\*\)\s*\(", 'mitre_id': 'T1557', 'blue_source': 'LDAP logs, application logs', 'remediation': 'LDAP filter escaping'},
        {'pattern': rb"objectClass\s*=", 'mitre_id': 'T1557', 'blue_source': 'LDAP audit', 'remediation': 'Input validation'},
        {'pattern': rb"uid\s*=.*\*", 'mitre_id': 'T1557', 'blue_source': 'LDAP logs', 'remediation': 'Wildcard filtering'},
        {'pattern': rb"\*\)\(uid=", 'mitre_id': 'T1557', 'blue_source': 'LDAP logs', 'remediation': 'Filter validation'},
    ],
    'Kerberos': [
        {'pattern': rb"krbtgt", 'mitre_id': 'T1558', 'blue_source': 'Kerberos logs, DC event 4769', 'remediation': 'Monitor ticket requests, enforce strong encryption'},
        {'pattern': rb"RC4-HMAC", 'mitre_id': 'T1558.001', 'blue_source': 'Kerberos audit, Zeek logs', 'remediation': 'Disable RC4, require AES encryption'},
        {'pattern': rb"AS-REQ", 'mitre_id': 'T1558', 'blue_source': 'Network capture, Kerberos logs', 'remediation': 'Monitor frequency, rate limit'},
        {'pattern': rb"TGT.*request", 'mitre_id': 'T1550', 'blue_source': 'Kerberos logs, Domain Controller', 'remediation': 'Session tracking, anomaly detection'},
        {'pattern': rb"\$krb5asrep", 'mitre_id': 'T1558.003', 'blue_source': 'File system, memory dumps', 'remediation': 'Require pre-auth, monitor accounts'},
        {'pattern': rb"kerberoasting", 'mitre_id': 'T1558.001', 'blue_source': 'Kerberos logs, Network IDS', 'remediation': 'Service account rotation, strong passwords'},
    ],
    'Bloodhound': [
        {'pattern': rb"(samaccountname|admincount|memberof)", 'mitre_id': 'T1087', 'blue_source': 'LDAP logs, Sysmon event 3', 'remediation': 'Monitor LDAP queries, restrict AD queries'},
        {'pattern': rb"(netsession|netlogon|lsassession)", 'mitre_id': 'T1135', 'blue_source': 'Network logs, Sysmon', 'remediation': 'Disable null sessions, restrict NetBIOS'},
        {'pattern': rb"SharpHound", 'mitre_id': 'T1087', 'blue_source': 'Process execution, EDR', 'remediation': 'Block tool, monitor AD queries'},
        {'pattern': rb"Get-ADUser|Get-ADComputer", 'mitre_id': 'T1087', 'blue_source': 'PowerShell logs, event 4104', 'remediation': 'Restrict PS AD cmdlets, enable transcription'},
        {'pattern': rb"(msds-allowedtodelegateto|serviceprincipalname)", 'mitre_id': 'T1558.001', 'blue_source': 'AD audit, LDAP logs', 'remediation': 'Monitor delegation, restrict settings'},
    ],
    'NMAP': [
        {'pattern': rb"(SYN|FIN|NULL|ACK|Xmas).*scan", 'mitre_id': 'T1046', 'blue_source': 'IDS/IPS, Firewall logs', 'remediation': 'Port security, DPI, rate limiting'},
        {'pattern': rb"Nmap", 'mitre_id': 'T1046', 'blue_source': 'Process logs, network telemetry', 'remediation': 'Block scanning tools, egress filtering'},
        {'pattern': rb"Zenmap", 'mitre_id': 'T1046', 'blue_source': 'EDR, network monitoring', 'remediation': 'Restrict tool usage'},
        {'pattern': rb"traceroute|mtr", 'mitre_id': 'T1046', 'blue_source': 'Network monitoring, firewall logs', 'remediation': 'Restrict ICMP, TTL responses'},
    ],
    'DDOS': [
        {'pattern': rb"(syn.*flood|syn.*storm)", 'mitre_id': 'T1498', 'blue_source': 'IDS/IPS, DDoS mitigation', 'remediation': 'SYN cookies, rate limiting, BGP filtering'},
        {'pattern': rb"(udp.*flood|udp.*amplification)", 'mitre_id': 'T1498', 'blue_source': 'NetFlow, packet analysis', 'remediation': 'Rate limiting, protocol filtering'},
        {'pattern': rb"(icmp.*flood|ping.*flood)", 'mitre_id': 'T1498', 'blue_source': 'IDS, firewall logs', 'remediation': 'ICMP rate limiting, blocking'},
        {'pattern': rb"(http.*flood|slowloris)", 'mitre_id': 'T1499', 'blue_source': 'WAF, web server logs', 'remediation': 'WAF rules, connection limits'},
        {'pattern': rb"(dns.*amplification|dns.*flood)", 'mitre_id': 'T1498.002', 'blue_source': 'DNS logs, NetFlow', 'remediation': 'DNS rate limiting, response filtering'},
        {'pattern': rb"(ntp.*amplification|ntp.*flood)", 'mitre_id': 'T1498.002', 'blue_source': 'NTP logs, IDS', 'remediation': 'Restrict NTP queries, update systems'},
    ],
    'Exfiltration': [
        {'pattern': rb"(scp|sftp|rsync).*transfer", 'mitre_id': 'T1020', 'blue_source': 'Network monitoring, firewall logs', 'remediation': 'Egress filtering, DLP, encrypt data'},
        {'pattern': rb"(ftp|ftps).*password", 'mitre_id': 'T1011', 'blue_source': 'Network IDS, packet capture', 'remediation': 'Disable FTP, enforce SFTP/FTPS'},
        {'pattern': rb"base64.*encode", 'mitre_id': 'T1001', 'blue_source': 'Application logs, DLP', 'remediation': 'Data loss prevention, encryption'},
        {'pattern': rb"(curl|wget).*http.*data", 'mitre_id': 'T1048.003', 'blue_source': 'Process logs, egress monitoring', 'remediation': 'Restrict outbound HTTP, use proxies'},
    ],
    'Lateral Movement': [
        {'pattern': rb"(psexec|wmic|at|task|schtasks)", 'mitre_id': 'T1047', 'blue_source': 'Sysmon, Windows event logs', 'remediation': 'Disable tools, restrict admin shares'},
        {'pattern': rb"(\\\\\\\\.*\\\\admin\$|\\\\\\\\.*\\\\c\$)", 'mitre_id': 'T1570', 'blue_source': 'Firewall logs, Sysmon event 3', 'remediation': 'Block admin shares, network segmentation'},
        {'pattern': rb"(ssh.*key|authorized_keys)", 'mitre_id': 'T1098.004', 'blue_source': 'File access logs, auditd', 'remediation': 'SSH key rotation, SSH hardening'},
        {'pattern': rb"(rsh|rexec|telnet)", 'mitre_id': 'T1570', 'blue_source': 'Network IDS, firewall', 'remediation': 'Disable insecure protocols, use SSH'},
    ],
    'DNS Tunnel': [
        {'pattern': rb"(dns.*over.*https|doh)", 'mitre_id': 'T1048.003', 'blue_source': 'DNS logs, network monitoring', 'remediation': 'Monitor DNS, restrict DoH'},
        {'pattern': rb"(dns.*data|txt.*record.*data)", 'mitre_id': 'T1048.003', 'blue_source': 'DNS logs, packet inspection', 'remediation': 'DNS filtering, DLP'},
        {'pattern': rb"(dnscat|iodine)", 'mitre_id': 'T1572', 'blue_source': 'Process logs, network IDS', 'remediation': 'Block tunneling tools, DNS filtering'},
    ],
    'SSH Brute': [
        {'pattern': rb"(ssh.*auth.*fail|ssh.*invalid.*user)", 'mitre_id': 'T1110', 'blue_source': 'SSH logs, Syslog', 'remediation': 'Key-based auth, fail2ban, rate limiting'},
        {'pattern': rb"(ssh.*password.*attempt|ssh.*brute)", 'mitre_id': 'T1110.001', 'blue_source': 'Auth logs, IDS', 'remediation': 'Disable password auth, use keys'},
        {'pattern': rb"(root.*login|admin.*ssh)", 'mitre_id': 'T1021.004', 'blue_source': 'SSH logs, Sysmon', 'remediation': 'Disable root login, use sudo'},
    ],
    'Credential Dumping': [
        {'pattern': rb"(mimikatz|hashdump|pwdump)", 'mitre_id': 'T1003', 'blue_source': 'EDR, Sysmon, process logs', 'remediation': 'Block tools, memory protection, LSASS hardening'},
        {'pattern': rb"(lsass|ntds\.dit|sam.*dump)", 'mitre_id': 'T1003.001', 'blue_source': 'File access logs, Sysmon', 'remediation': 'Protect LSASS, file ACLs, encryption'},
        {'pattern': rb"(credential.*cache|kerberos.*dump)", 'mitre_id': 'T1003.008', 'blue_source': 'Memory forensics, EDR', 'remediation': 'Credential Guard, memory encryption'},
        {'pattern': rb"(registry.*dump|secretsdump)", 'mitre_id': 'T1003.002', 'blue_source': 'Registry audit, EDR', 'remediation': 'Registry ACLs, monitoring'},
    ],
    'BufferOverflow': [
        {'pattern': rb"([\x00-\xff])\1{99,}", 'mitre_id': 'T1210', 'blue_source': 'IDS/IPS signatures, crash dumps, EDR', 'remediation': 'Input length validation, ASLR/DEP/stack canaries, patch vulnerable service'},
        {'pattern': rb"\x90{20,}", 'mitre_id': 'T1203', 'blue_source': 'IDS/IPS (NOP sled detection), memory forensics', 'remediation': 'DEP/NX enforcement, patch vulnerable service'},
        {'pattern': rb"(%x){4,}|%n|%s{5,}", 'mitre_id': 'T1203', 'blue_source': 'Application crash logs, WAF logs', 'remediation': 'Fix format string usage, input validation'},
        {'pattern': rb"\x31\xc0\x50\x68", 'mitre_id': 'T1203', 'blue_source': 'IDS/IPS shellcode signatures, EDR', 'remediation': 'DEP/NX enforcement, patch vulnerable service'},
    ],
}

SYN_SCAN_THRESHOLD = 10
PCAP_MAGIC = {0xa1b2c3d4: '<', 0xd4c3b2a1: '>', 0xa1b23c4d: '<', 0x4d3cb2a1: '>'}
MAX_STREAM_BUFFER = 8192

def detect_exploits_raw(pcap_path):
    alerts = []
    syn_count = defaultdict(lambda: defaultdict(int))
    flows = defaultdict(lambda: {'pkts': 0, 'bytes': 0})
    stream_buf = defaultdict(bytes)
    stream_alerted = set()
    pkt_num = 0

    with open(pcap_path, 'rb') as f:
        header = f.read(4)
        if len(header) < 4:
            raise ValueError("Empty or truncated PCAP file")
        magic = struct.unpack('<I', header)[0]
        if magic not in PCAP_MAGIC:
            raise ValueError(f"Not a valid PCAP file (magic={hex(magic)})")
        endian = PCAP_MAGIC[magic]
        f.read(20)

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break

            pkt_num += 1
            ts_sec, ts_usec, inc_len, orig_len = struct.unpack(f'{endian}IIII', pkt_hdr)
            pkt_data = f.read(inc_len)
            if len(pkt_data) < inc_len:
                break

            if len(pkt_data) < 14:
                continue

            eth_type = struct.unpack('>H', pkt_data[12:14])[0]
            offset = 14
            if eth_type == 0x8100:
                if len(pkt_data) < 18:
                    continue
                eth_type = struct.unpack('>H', pkt_data[16:18])[0]
                offset = 18
            if eth_type != 0x0800 or len(pkt_data) < offset + 20:
                continue

            ip_hdr = pkt_data[offset:offset+20]
            ihl = (ip_hdr[0] & 0x0f) * 4
            proto = ip_hdr[9]
            src_ip = socket.inet_ntoa(ip_hdr[12:16])
            dst_ip = socket.inet_ntoa(ip_hdr[16:20])
            l4 = offset + ihl

            if proto == 6 and len(pkt_data) >= l4 + 14:
                tcp_hdr = pkt_data[l4:l4+14]
                src_port, dst_port = struct.unpack('>HH', tcp_hdr[0:4])
                flags = tcp_hdr[13]
                syn_flag = (flags & 0x02) != 0

                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                flows[flow_key]['pkts'] += 1
                flows[flow_key]['bytes'] += orig_len

                if syn_flag:
                    syn_count[src_ip][dst_ip] += 1
                    if syn_count[src_ip][dst_ip] == SYN_SCAN_THRESHOLD:
                        alerts.append({
                            'src': src_ip, 'dst': dst_ip, 'type': 'SYN Scan',
                            'mitre': 'T1046', 'blue': 'IDS/IPS, Firewall logs',
                            'fix': 'Port security, rate limiting', 'pkt': pkt_num,
                            'ts': ts_sec, 'severity': SEVERITY_MAP['SYN Scan']
                        })

                payload_start = l4 + 20
                if len(pkt_data) > payload_start:
                    payload = pkt_data[payload_start:]
                    buf = (stream_buf[flow_key] + payload)[-MAX_STREAM_BUFFER:]
                    stream_buf[flow_key] = buf
                    texty = _is_texty(buf)
                    for exploit_type, sigs in SIGNATURES.items():
                        if exploit_type not in BINARY_SCOPE_TYPES and not texty:
                            continue
                        dedupe_key = (flow_key, exploit_type)
                        if dedupe_key in stream_alerted:
                            continue
                        for sig in sigs:
                            if re.search(sig['pattern'], buf, re.IGNORECASE):
                                alerts.append({
                                    'src': src_ip, 'dst': dst_ip, 'type': exploit_type,
                                    'mitre': sig['mitre_id'], 'blue': sig['blue_source'],
                                    'fix': sig['remediation'], 'pkt': pkt_num, 'ts': ts_sec,
                                    'severity': SEVERITY_MAP[exploit_type],
                                    'payload_preview': buf[-100:].decode('latin-1', errors='replace')
                                })
                                stream_alerted.add(dedupe_key)
                                break

            elif proto == 17 and len(pkt_data) >= l4 + 8:
                src_port, dst_port = struct.unpack('>HH', pkt_data[l4:l4+4])
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                flows[flow_key]['pkts'] += 1
                flows[flow_key]['bytes'] += orig_len

                payload_start = l4 + 8
                if len(pkt_data) > payload_start:
                    payload = pkt_data[payload_start:]
                    texty = _is_texty(payload)
                    for exploit_type, sigs in SIGNATURES.items():
                        if exploit_type not in BINARY_SCOPE_TYPES and not texty:
                            continue
                        for sig in sigs:
                            if re.search(sig['pattern'], payload, re.IGNORECASE):
                                alerts.append({
                                    'src': src_ip, 'dst': dst_ip, 'type': exploit_type,
                                    'mitre': sig['mitre_id'], 'blue': sig['blue_source'],
                                    'fix': sig['remediation'], 'pkt': pkt_num, 'ts': ts_sec,
                                    'severity': SEVERITY_MAP[exploit_type],
                                    'payload_preview': payload[:100].decode('latin-1', errors='replace')
                                })
                                break

    return alerts, flows

def detect_exploits_tshark(pcap_path, tshark_path):
    alerts = []
    syn_count = defaultdict(lambda: defaultdict(int))
    flows = defaultdict(lambda: {'pkts': 0, 'bytes': 0})
    stream_buf = defaultdict(bytes)
    stream_alerted = set()
    pkt_num = 0

    cmd = [tshark_path, '-r', pcap_path, '-T', 'fields', '-E', 'separator=\t', '-E', 'occurrence=f']
    for field in TSHARK_FIELDS:
        cmd += ['-e', field]

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding='utf-8', errors='replace'
    )

    for line in proc.stdout:
        cols = line.rstrip('\n').split('\t')
        if len(cols) < len(TSHARK_FIELDS):
            cols += [''] * (len(TSHARK_FIELDS) - len(cols))
        row = dict(zip(TSHARK_FIELDS, cols))

        pkt_num += 1
        try:
            ts_sec = int(float(row['frame.time_epoch'])) if row['frame.time_epoch'] else 0
            orig_len = int(row['frame.len']) if row['frame.len'] else 0
        except ValueError:
            ts_sec, orig_len = 0, 0

        src_ip, dst_ip = row['ip.src'], row['ip.dst']
        if not src_ip or not dst_ip:
            continue

        src_port = row['tcp.srcport'] or row['udp.srcport'] or '0'
        dst_port = row['tcp.dstport'] or row['udp.dstport'] or '0'
        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        flows[flow_key]['pkts'] += 1
        flows[flow_key]['bytes'] += orig_len

        if row['tcp.flags.syn'] in ('1', 'True') and row['tcp.flags.ack'] not in ('1', 'True'):
            syn_count[src_ip][dst_ip] += 1
            if syn_count[src_ip][dst_ip] == SYN_SCAN_THRESHOLD:
                alerts.append({
                    'src': src_ip, 'dst': dst_ip, 'type': 'SYN Scan',
                    'mitre': 'T1046', 'blue': 'IDS/IPS, Firewall logs',
                    'fix': 'Port security, rate limiting', 'pkt': pkt_num,
                    'ts': ts_sec, 'severity': SEVERITY_MAP['SYN Scan']
                })

        http_text = ' '.join(filter(None, [
            row['http.request.method'], row['http.request.uri'],
            row['http.request.line'], row['http.file_data']
        ]))
        dns_text = row['dns.qry.name']
        tcp_raw = _hexfield_to_bytes(row['tcp.payload'])
        udp_raw = _hexfield_to_bytes(row['udp.payload'])
        pkt_generic_text = (tcp_raw or udp_raw)
        pkt_generic_text = pkt_generic_text.decode('latin-1', errors='replace') if _is_texty(pkt_generic_text) else ''

        if tcp_raw:
            stream_bytes = (stream_buf[flow_key] + tcp_raw)[-MAX_STREAM_BUFFER:]
            stream_buf[flow_key] = stream_bytes
        else:
            stream_bytes = tcp_raw or udp_raw
        stream_raw_text = stream_bytes.decode('latin-1', errors='replace')
        stream_text = stream_raw_text if _is_texty(stream_bytes) else ''

        for exploit_type, sigs in SIGNATURES.items():
            dedupe_key = None
            if exploit_type in HTTP_SCOPE_TYPES:
                haystack = http_text or pkt_generic_text
            elif exploit_type in DNS_SCOPE_TYPES:
                haystack = dns_text or pkt_generic_text
            elif exploit_type in BINARY_SCOPE_TYPES:
                haystack = stream_raw_text
                dedupe_key = (flow_key, exploit_type)
            else:
                haystack = stream_text
                dedupe_key = (flow_key, exploit_type)
            if not haystack or (dedupe_key and dedupe_key in stream_alerted):
                continue
            haystack_bytes = haystack.encode('latin-1', errors='replace')
            for sig in sigs:
                if re.search(sig['pattern'], haystack_bytes, re.IGNORECASE):
                    alerts.append({
                        'src': src_ip, 'dst': dst_ip, 'type': exploit_type,
                        'mitre': sig['mitre_id'], 'blue': sig['blue_source'],
                        'fix': sig['remediation'], 'pkt': pkt_num, 'ts': ts_sec,
                        'severity': SEVERITY_MAP[exploit_type],
                        'payload_preview': haystack[-100:]
                    })
                    if dedupe_key:
                        stream_alerted.add(dedupe_key)
                    break

    stderr = proc.stderr.read()
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"tshark exited with code {proc.returncode}: {stderr.strip()[:200]}")

    return alerts, flows

def detect_exploits(pcap_path):
    tshark_path = find_tshark()
    if tshark_path:
        try:
            alerts, flows = detect_exploits_tshark(pcap_path, tshark_path)
            return alerts, flows, 'tshark'
        except Exception as e:
            print(f"[WARNING] tshark engine failed ({e}); falling back to raw-byte parser", file=sys.stderr)

    alerts, flows = detect_exploits_raw(pcap_path)
    return alerts, flows, 'raw-byte fallback'

def write_json_report(alerts, flows, out_path, engine='unknown'):
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({'alerts': alerts, 'flows': flows, 'engine': engine, 'summary': {
            'total_alerts': len(alerts),
            'critical': sum(1 for a in alerts if a['severity'] >= 9),
            'high': sum(1 for a in alerts if 7 <= a['severity'] < 9),
            'medium': sum(1 for a in alerts if 5 <= a['severity'] < 7),
        }}, f, indent=2, default=str)

def write_csv_report(alerts, out_path):
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['pkt', 'ts', 'src', 'dst', 'type', 'severity', 'mitre', 'blue', 'fix'])
        writer.writeheader()
        for a in alerts:
            writer.writerow({k: a.get(k) for k in writer.fieldnames})

def write_md_report(alerts, flows, out_path, engine='unknown'):
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# Integrated Security Analysis Report\n\n")
        f.write(f"**Detection Engine**: {engine}\n\n")
        f.write(f"**Total Alerts**: {len(alerts)} | **Critical**: {sum(1 for a in alerts if a['severity'] >= 9)} | ")
        f.write(f"**High**: {sum(1 for a in alerts if 7 <= a['severity'] < 9)} | **Medium**: {sum(1 for a in alerts if 5 <= a['severity'] < 7)}\n\n")

        f.write("## Top Attackers\n")
        attackers = defaultdict(int)
        for a in alerts:
            attackers[a['src']] += 1
        for ip, cnt in sorted(attackers.items(), key=lambda x: x[1], reverse=True)[:5]:
            f.write(f"- {ip}: {cnt} alerts\n")

        f.write("\n## Top Targets\n")
        targets = defaultdict(int)
        for a in alerts:
            targets[a['dst']] += 1
        for ip, cnt in sorted(targets.items(), key=lambda x: x[1], reverse=True)[:5]:
            f.write(f"- {ip}: {cnt} alerts\n")

        f.write("\n## Critical/High Alerts\n")
        f.write("| Packet | Src | Dst | Attack | MITRE | Severity |\n|---|---|---|---|---|---|\n")
        for a in sorted(alerts, key=lambda x: x['severity'], reverse=True):
            if a['severity'] >= 7:
                f.write(f"| {a['pkt']} | {a['src']} | {a['dst']} | {a['type']} | {a['mitre']} | {a['severity']} |\n")

        f.write("\n## Network Flows\n")
        f.write("| Source | Destination | Packets | Bytes |\n|---|---|---|---|\n")
        for flow, stats in sorted(flows.items(), key=lambda x: x[1]['bytes'], reverse=True)[:10]:
            f.write(f"| {flow.split('-')[0]} | {flow.split('-')[1]} | {stats['pkts']} | {stats['bytes']} |\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python enhanced_detector.py <pcap_file> [--json|--csv|--md|--all]")
        sys.exit(1)

    pcap = sys.argv[1]
    fmt = sys.argv[2].strip('-') if len(sys.argv) > 2 else 'md'

    if not Path(pcap).exists():
        print(f"[ERROR] File not found: {pcap}")
        sys.exit(1)

    try:
        alerts, flows, engine = detect_exploits(pcap)
    except Exception as e:
        print(f"[ERROR] Failed to parse PCAP: {e}")
        sys.exit(1)

    stem = str(Path(pcap).stem)
    written = []

    if fmt in ('json', 'all'):
        out = f"{stem}_analysis.json"
        write_json_report(alerts, flows, out, engine)
        written.append(out)
    if fmt in ('csv', 'all'):
        out = f"{stem}_alerts.csv"
        write_csv_report(alerts, out)
        written.append(out)
    if fmt in ('md', 'all'):
        out = f"{stem}_analysis.md"
        write_md_report(alerts, flows, out, engine)
        written.append(out)

    for out in written:
        print(f"[OK] Report written to {out}")
    print(f"[INFO] Detection engine used: {engine}")
