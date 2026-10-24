
import hashlib
import json
import platform
import socket
import getpass
import psutil

from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "evidence"


def get_utc_timestamp():
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def collect_host_metadata():
    """Collect basic host and operating system metadata."""
    return {
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "collection_timestamp_utc": get_utc_timestamp(),
    }


def collect_running_processes():
    """Collect information about currently running processes."""
    processes = []

    process_attributes = [
        "pid",
        "name",
        "exe",
        "cmdline",
        "username",
        "create_time",
        "status",
    ]

    print("[*] Collecting running process information...")

    for process in psutil.process_iter(attrs=process_attributes):
        try:
            process_info = process.info

            processes.append({
                "pid": process_info.get("pid"),
                "name": process_info.get("name"),
                "executable_path": process_info.get("exe"),
                "command_line": process_info.get("cmdline"),
                "username": process_info.get("username"),
                "creation_time": process_info.get("create_time"),
                "status": process_info.get("status"),
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # A process may exit or become inaccessible during collection.
            continue

    return {
        "collection_timestamp_utc": get_utc_timestamp(),
        "total_processes_collected": len(processes),
        "processes": processes,
    }


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def save_evidence(data, output_path):
    """Save collected data as formatted JSON."""
    with open(output_path, "w", encoding="utf-8") as evidence_file:
        json.dump(data, evidence_file, indent=4)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    collection_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    collection_dir = OUTPUT_DIR / f"collection_{collection_id}"
    collection_dir.mkdir(parents=True, exist_ok=True)

    host_metadata_path = collection_dir / "host_metadata.json"
    processes_path = collection_dir / "running_processes.json"
    manifest_path = collection_dir / "manifest.json"

    print("[*] Starting DFIR Analyzer evidence collection...")

    # Collect host metadata.
    metadata = collect_host_metadata()
    save_evidence(metadata, host_metadata_path)

    # Collect running processes.
    process_data = collect_running_processes()
    save_evidence(process_data, processes_path)

    # Calculate evidence hashes.
    evidence_files = []

    for evidence_path in [host_metadata_path, processes_path]:
        evidence_files.append({
            "filename": evidence_path.name,
            "sha256": calculate_sha256(evidence_path),
            "hash_algorithm": "SHA-256",
        })

    # Create manifest.
    manifest = {
        "collection_id": collection_id,
        "collection_timestamp_utc": get_utc_timestamp(),
        "collector": "DFIR Analyzer",
        "evidence_files": evidence_files,
    }

    save_evidence(manifest, manifest_path)

    print("[+] Host metadata collected.")
    print(f"[+] Processes collected: {process_data['total_processes_collected']}")
    print(f"[+] Evidence saved to: {collection_dir}")
    print("[+] Manifest created with SHA-256 hashes.")


if __name__ == "__main__":
    main()
