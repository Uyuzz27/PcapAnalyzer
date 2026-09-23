import os
import sys
import subprocess
import logging
from pathlib import Path
from datetime import datetime

ANALYZER_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(ANALYZER_DIR, "input")
OUTPUT_DIR = os.path.join(ANALYZER_DIR, "output")
LOG_DIR = os.path.join(ANALYZER_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

Path(LOG_DIR).mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def setup_dirs():
    Path(INPUT_DIR).mkdir(exist_ok=True)
    Path(OUTPUT_DIR).mkdir(exist_ok=True)
    logger.debug(f"Input dir: {INPUT_DIR}")
    logger.debug(f"Output dir: {OUTPUT_DIR}")

def analyze_pcap(pcap_path, output_dir):
    pcap_name = Path(pcap_path).name
    logger.info(f"Starting analysis: {pcap_name}")

    try:
        logger.debug(f"Running enhanced_detector.py")
        result = subprocess.run(
            [sys.executable, 'enhanced_detector.py', pcap_path, '--all'],
            cwd=ANALYZER_DIR,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            logger.error(f"Detection failed: {result.stderr}")
            return False

        logger.debug("Detection completed successfully")

        stem = Path(pcap_path).stem
        json_file = os.path.join(ANALYZER_DIR, f"{stem}_analysis.json")

        result = subprocess.run(
            [sys.executable, 'master_report.py', pcap_path, json_file],
            cwd=ANALYZER_DIR,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            logger.error(f"Master report failed: {result.stderr}")
            return False

        logger.debug("Master report generated")

        result = subprocess.run(
            [sys.executable, 'role_reports.py', pcap_path, json_file],
            cwd=ANALYZER_DIR,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            logger.warning(f"Role reports skipped: {result.stderr}")
        else:
            logger.debug("Role reports generated")

        move_outputs(stem, output_dir)

        logger.info(f"Analysis complete: {pcap_name}")
        return True

    except Exception as e:
        logger.exception(f"Error analyzing {pcap_name}")
        return False

def move_outputs(stem, output_dir):
    import glob
    import shutil

    patterns = [
        f"{stem}_*.md",
        f"{stem}_*.csv",
        f"{stem}_*.json",
    ]

    for pattern in patterns:
        for file in glob.glob(os.path.join(ANALYZER_DIR, pattern)):
            try:
                src = file
                dst = os.path.join(output_dir, os.path.basename(file))
                shutil.move(src, dst)
                logger.debug(f"Moved file: {os.path.basename(file)}")
            except Exception as e:
                logger.warning(f"Could not move {os.path.basename(file)}: {e}")

def main():
    setup_dirs()
    logger.info("PCAP Analyzer - Batch Analysis Tool started")

    pcap_files = list(Path(INPUT_DIR).glob("*.pcap")) + list(Path(INPUT_DIR).glob("*.pcapng"))

    if not pcap_files:
        logger.warning(f"No PCAP files found in {INPUT_DIR}/")
        return

    logger.info(f"Found {len(pcap_files)} PCAP file(s) to analyze")
    for i, pcap in enumerate(pcap_files, 1):
        size_mb = pcap.stat().st_size / (1024*1024)
        logger.debug(f"File {i}: {pcap.name} ({size_mb:.2f} MB)")

    successful = 0
    failed = 0

    for pcap_path in pcap_files:
        if analyze_pcap(str(pcap_path), OUTPUT_DIR):
            successful += 1
        else:
            failed += 1

    logger.info(f"Batch analysis complete: {successful} successful, {failed} failed")
    logger.info(f"Reports saved to: {OUTPUT_DIR}/")

    if successful > 0:
        output_files = sorted(Path(OUTPUT_DIR).glob("*"))
        logger.info(f"Generated {len(output_files)} output files")

if __name__ == "__main__":
    main()
