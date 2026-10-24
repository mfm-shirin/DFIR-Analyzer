
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
ANALYSIS_DIR = PROJECT_ROOT / "analysis"


def get_latest_collection():
    """Find the newest evidence collection folder."""

    collection_folders = [
        folder
        for folder in EVIDENCE_DIR.glob("collection_*")
        if folder.is_dir()
    ]

    if not collection_folders:
        raise FileNotFoundError(
            "No evidence collection folders were found."
        )

    # Collection folder names contain timestamps:
    # collection_YYYYMMDD_HHMMSS
    return max(collection_folders, key=lambda folder: folder.name)


def load_json(file_path):
    """Load and return data from a JSON file."""

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def analyse_processes(collection_path):
    """Analyse running process evidence."""

    process_file = collection_path / "running_processes.json"

    if not process_file.exists():
        raise FileNotFoundError(
            f"Missing evidence file: {process_file}"
        )

    process_data = load_json(process_file)

    # Support the list format produced by our collector.
    if isinstance(process_data, list):
        processes = process_data

    # Also support a dictionary containing a process list.
    elif isinstance(process_data, dict):
        processes = process_data.get("processes", [])

    else:
        raise ValueError(
            "Unexpected format in running_processes.json"
        )

    findings = []

    for process in processes:
        if not isinstance(process, dict):
            continue

        pid = process.get("pid")
        name = process.get("name")
        executable = process.get("executable_path")

        # Missing executable paths can be worth investigating.
        # This is an indicator, not proof of malicious activity.
        if not executable:
            findings.append({
                "type": "missing_executable_path",
                "severity": "low",
                "pid": pid,
                "process_name": name,
                "description": (
                    "The process does not have an accessible "
                    "executable path."
                )
            })

    report = {
        "analysis_timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "collection_path": str(collection_path),
        "total_processes": len(processes),
        "findings_count": len(findings),
        "findings": findings
    }

    return report


def save_report(report, collection_path):
    """Save the analysis report as JSON."""

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

    report_name = f"analysis_{collection_path.name}.json"
    report_path = ANALYSIS_DIR / report_name

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report_path


def main():
    parser = argparse.ArgumentParser(
        description="DFIR Analyzer - Evidence Analysis"
    )

    parser.add_argument(
        "--collection",
        type=Path,
        help=(
            "Path to a specific evidence collection folder. "
            "If omitted, the latest collection is selected."
        )
    )

    args = parser.parse_args()

    try:
        if args.collection:
            collection_path = args.collection.resolve()

            if not collection_path.is_dir():
                raise FileNotFoundError(
                    "The specified collection folder does not exist."
                )

        else:
            collection_path = get_latest_collection()

        print(f"\nSelected collection: {collection_path.name}")

        report = analyse_processes(collection_path)

        report_path = save_report(
            report,
            collection_path
        )

        print("\nAnalysis completed!")
        print(f"Total processes: {report['total_processes']}")
        print(f"Findings: {report['findings_count']}")
        print(f"Report saved to: {report_path}")

    except (FileNotFoundError, ValueError, json.JSONDecodeError) as error:
        print(f"\nAnalysis failed: {error}")


if __name__ == "__main__":
    main()
