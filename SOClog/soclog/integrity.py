import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Optional


def sha256_file(path: str) -> str:
    """Compute SHA-256 hash of a file on disk."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(
    files: List[str],
    host: str,
    collection_time: Optional[datetime] = None,
) -> Dict:
    """
    Build a manifest dictionary containing file info and hashes.

    files: list of absolute file paths
    host: hostname or label
    """
    if collection_time is None:
        collection_time = datetime.now(timezone.utc)

    records = []
    for path in files:
        stat = os.stat(path)
        records.append(
            {
                "file_name": os.path.basename(path),
                "relative_path": os.path.basename(path),
                "size_bytes": stat.st_size,
                "sha256": sha256_file(path),
                "mtime_utc": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).isoformat(),
            }
        )

    manifest = {
        "host": host,
        "generated_at_utc": collection_time.isoformat(),
        "files": records,
    }
    return manifest


def write_manifest(manifest: Dict, output_path: str) -> None:
    """Write the manifest to disk as JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)


def sign_manifest_with_gpg(
    manifest_path: str,
    output_sig_path: str,
    gpg_key: Optional[str] = None,
) -> None:
    """
    Create a detached signature (ASCII armored) for the manifest using GPG.

    gpg_key:
      - If provided: used as -u KEYID.
      - If None: GPG default key is used.
    """
    cmd = ["gpg", "--armor", "--output", output_sig_path, "--detach-sign"]

    if gpg_key:
        cmd.extend(["-u", gpg_key])

    cmd.append(manifest_path)

    subprocess.run(cmd, check=True)
