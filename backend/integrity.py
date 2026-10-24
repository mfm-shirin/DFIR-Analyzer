
import hashlib
import json
from pathlib import Path


def calculate_sha256(file_path: Path) -> str:
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def verify_collection(collection_dir: Path) -> dict:
    """Verify evidence files against the collection manifest."""
    collection_dir = Path(collection_dir)
    manifest_path = collection_dir / "manifest.json"

    if not manifest_path.exists():
        return {
            "status": "error",
            "message": "Manifest file is missing.",
            "total_files": 0,
            "verified_files": 0,
            "modified_files": [],
            "missing_files": [],
            "results": [],
        }

    try:
        with open(manifest_path, "r", encoding="utf-8") as manifest_file:
            manifest = json.load(manifest_file)
    except (json.JSONDecodeError, OSError) as error:
        return {
            "status": "error",
            "message": f"Unable to read manifest: {error}",
            "total_files": 0,
            "verified_files": 0,
            "modified_files": [],
            "missing_files": [],
            "results": [],
        }

    evidence_files = manifest.get("evidence_files", [])
    results = []
    modified_files = []
    missing_files = []
    verified_files = 0

    for evidence in evidence_files:
        filename = evidence.get("filename")
        expected_hash = evidence.get("sha256")

        if not filename or not expected_hash:
            results.append({
                "filename": filename or "Unknown",
                "status": "invalid_manifest_entry",
            })
            continue

        # Prevent manifest entries from escaping the collection directory.
        evidence_path = (collection_dir / filename).resolve()

        if evidence_path.parent != collection_dir.resolve():
            results.append({
                "filename": filename,
                "status": "invalid_path",
            })
            continue

        if not evidence_path.is_file():
            missing_files.append(filename)
            results.append({
                "filename": filename,
                "status": "missing",
                "expected_sha256": expected_hash,
            })
            continue

        actual_hash = calculate_sha256(evidence_path)

        if actual_hash == expected_hash:
            verified_files += 1
            results.append({
                "filename": filename,
                "status": "verified",
                "sha256": actual_hash,
            })
        else:
            modified_files.append(filename)
            results.append({
                "filename": filename,
                "status": "modified",
                "expected_sha256": expected_hash,
                "actual_sha256": actual_hash,
            })

    if modified_files or missing_files:
        status = "failed"
        message = "Evidence integrity verification failed."
    elif verified_files == len(evidence_files):
        status = "verified"
        message = "All evidence files passed integrity verification."
    else:
        status = "incomplete"
        message = "Some manifest entries could not be verified."

    return {
        "status": status,
        "message": message,
        "total_files": len(evidence_files),
        "verified_files": verified_files,
        "modified_files": modified_files,
        "missing_files": missing_files,
        "results": results,
    }
