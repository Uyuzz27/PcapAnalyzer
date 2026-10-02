# PCAP Analyzer

Stream-based PCAP threat detector and multi-role security reporting tool. Pure Python standard library — no dependencies, no installation.

## Legal / Responsible Use

This tool is for analyzing PCAPs you are authorized to inspect — incident response, your own lab/CTF captures, or engagements you have written permission for. The signature set includes patterns for exploit payloads (SQLi, RCE, buffer overflow shellcode markers, etc.) for detection purposes only; it contains no exploit code. You are responsible for how you use it and for complying with applicable laws and organizational policy.

## Requirements

- Python 3.7+ (verify with `python --version`)
- No third-party packages required
- **Optional**: Wireshark (`tshark`) installed — auto-detected, enables the higher-precision protocol-aware detection engine. Not required; the tool works fully without it, just with more false positives (see [Detection Engine](#detection-engine)).

## Folder Structure

```
PCAP Analyzer/
├── input/              Place .pcap / .pcapng files here
├── output/              Generated reports land here
├── logs/                Timestamped debug logs from each run
├── run.bat              Double-click to analyze everything in input/
├── run_analysis.py      Batch driver (input/ -> output/), used by run.bat
├── enhanced_detector.py Core PCAP parser + 130+ exploit signatures
├── master_report.py     Builds the single all-teams MASTER_REPORT.md
├── role_reports.py      Builds the 7 role-specific reports
└── CREATE_DESKTOP_SHORTCUT.bat  Optional: adds a desktop shortcut to run.bat
```

## Quick Start (no command line)

1. Copy your `.pcap` / `.pcapng` file(s) into `input/`.
2. Double-click `run.bat`.
3. When done, reports are in `output/` (the script offers to open the folder).
4. Debug logs for the run are saved in `logs/analysis_<timestamp>.log`.

Optional: run `CREATE_DESKTOP_SHORTCUT.bat` once to add a "PCAP Analyzer" shortcut to your Desktop.

## Command Line Usage

Batch mode (everything in `input/`):
```bash
python run_analysis.py
```

Single file, full pipeline (JSON + CSV + MD + master + role reports):
```bash
python enhanced_detector.py capture.pcap --all
python master_report.py capture.pcap capture_analysis.json
python role_reports.py capture.pcap capture_analysis.json
```

Single-format output only:
```bash
python enhanced_detector.py capture.pcap --json   # capture_analysis.json
python enhanced_detector.py capture.pcap --csv    # capture_alerts.csv
python enhanced_detector.py capture.pcap --md     # capture_analysis.md
```

## Output Files

| File | Audience | Content |
|---|---|---|
| `*_MASTER_REPORT.md` | **All teams** | Executive summary + every role's section in one file |
| `*_L1_report.md` | SOC L1 | Quick triage table, escalation counts |
| `*_L2_report.md` | SOC L2 | Alerts grouped by attack type, where to check logs |
| `*_L3_report.md` | SOC L3 | Full attack timeline, MITRE mapping, remediation |
| `*_pentester_report.md` | Pentester | Findings grouped by severity, evidence for reports |
| `*_blue_report.md` | Blue Team | Detection rate per attack type, validation sources |
| `*_purple_report.md` | Purple Team | Red findings vs. blue detection coverage map |
| `*_network_report.md` | Network Team | Top attackers/targets, suspicious flows |
| `*_analysis.md` | Anyone | Integrated summary (attackers, targets, flows) |
| `*_analysis.json` | Tooling/SIEM | Machine-readable alerts + flows |
| `*_alerts.csv` | Spreadsheets | Raw alert rows |

## Detection Coverage

18 categories, 130+ signatures, each mapped to a MITRE ATT&CK technique with a blue-team validation source and remediation:

SQLi, RCE, Command Injection, XXE, XSS, Path Traversal, LDAP Injection, SYN Scan, Kerberos abuse, BloodHound/AD recon, NMAP scanning, DDoS patterns, Data Exfiltration, Lateral Movement, DNS Tunneling, SSH Brute Force, Credential Dumping, **Buffer Overflow**.

Buffer Overflow detection is intentionally binary-aware: it matches NOP sleds (`\x90` runs), any single byte repeated 100+ times (catches both classic `AAAA...` fuzzing PoCs and raw shellcode padding), format-string attack patterns (`%x%x%x%x`, `%n`), and a common shellcode prologue marker — and is exempt from the printable-text filter that gates every other signature type, since shellcode is expected to be non-printable.

Severity is scored 1-9; anything >=9 is CRITICAL, 7-8 is HIGH, 5-6 is MEDIUM.

## Adding Signatures

Edit `SIGNATURES` and `SEVERITY_MAP` in `enhanced_detector.py`:
```python
SIGNATURES['YourAttack'] = [
    {'pattern': rb"your_regex", 'mitre_id': 'T1234',
     'blue_source': 'Your log source', 'remediation': 'Your fix'},
]
SEVERITY_MAP['YourAttack'] = 8
```

## Detection Engine

Two interchangeable engines produce identical alert schemas; every report shows which one ran (`Detection Engine: tshark` or `Detection Engine: raw-byte fallback`).

- **tshark (preferred, auto-detected)** — if Wireshark/`tshark.exe` is installed, it's used to actually decode protocols (HTTP request line/URI/body, DNS queries) instead of regex-matching raw bytes. Signatures for context-sensitive types (SQLi, XSS, XXE, Path Traversal) are matched only against the relevant decoded HTTP field, and DNS Tunnel signatures only against the DNS query name — this is what cuts false positives, since e.g. `union select` inside an HTTP URI is meaningful but the same bytes inside a TLS handshake or an image are not. All other signature types still scan the raw TCP/UDP payload, same as the fallback engine.
  - Auto-detected via (in order): `TSHARK_PATH` env var, `PATH`, then `C:\Program Files\Wireshark\tshark.exe`.
  - If tshark errors on a given file, the tool automatically falls back to the raw engine for that run (logged as a warning, not a failure).
- **raw-byte fallback (zero dependencies)** — the original `struct`-based Ethernet/IPv4/TCP/UDP parser. Used automatically when tshark isn't installed. Every payload is now also checked for printable-text ratio (>=60%) before signature matching, to avoid matching regex bytes against binary/encrypted noise.

Both engines: stream frame-by-frame (constant memory regardless of file size), track per-flow packet/byte counts, flag SYN-scan bursts, and reassemble TCP streams — the last 8KB of payload per flow (`MAX_STREAM_BUFFER` in `enhanced_detector.py`) is buffered so a signature split across two or more TCP segments is still caught, not just matches that happen to land inside one packet. Each alert type fires once per flow (not once per packet) once a stream matches, so a long-lived connection doesn't spam duplicate alerts. Assumes packets are processed in capture order (no out-of-order/retransmission reordering).

## How It Works

- `enhanced_detector.py` picks an engine (see above), parses the PCAP, and serializes `alerts`/`flows`/`engine` once to JSON; `master_report.py` and `role_reports.py` both consume that JSON so the PCAP is only parsed once per run.
- `run_analysis.py` orchestrates the three scripts for every file in `input/`, moves all generated reports into `output/`, and writes a timestamped debug log to `logs/`.

## Troubleshooting

- **"Python is not installed or not in PATH"**: install Python from python.org and check "Add Python to PATH".
- **No reports generated / role or master report skipped**: open the latest file in `logs/`; it contains the exact error and which step failed.
- **"Not a valid PCAP file"**: the input isn't a `.pcap`/`.pcapng` in libpcap format (e.g. it's a pcapng-only capture saved incorrectly, or corrupted). Re-export from Wireshark as "Wireshark/tcpdump/... - pcap".
- Reports use UTF-8 encoding throughout; console output is ASCII-only (`[OK]`/`[ERROR]`) to avoid Windows console codepage crashes.

## Performance

Stream parsing keeps memory flat regardless of file size; a typical 500 MB capture analyzes in well under a minute on standard hardware.

## License

No license file is currently included. Without one, default copyright applies and others technically can't legally use, modify, or redistribute this code even though it's on a public repo. Add a `LICENSE` file (MIT is the common choice for a tool like this) before or right after pushing if you want others to actually be able to use it.
