"""
SecureMailScope - Automated Archive Packager
Creates clean, standalone 'securemailscope.zip' containing all backend, frontend,
synthetic PCAPs, CA hierarchies, ML models, documentation, and docker assets.
"""

import os
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR
OUTPUT_ZIP = BASE_DIR.parent / "securemailscope.zip"

EXCLUDE_DIRS = {
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".git",
    ".idea",
    ".vscode",
    ".system_generated"
}

EXCLUDE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
}


def package_project():
    print(f"[*] Packaging SecureMailScope into: {OUTPUT_ZIP}")
    
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(PROJECT_ROOT):
            # Modify dirs in-place to skip excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

            for file in files:
                ext = os.path.splitext(file)[1]
                if ext in EXCLUDE_EXTENSIONS:
                    continue

                file_path = Path(root) / file
                # Relative path inside zip
                rel_path = file_path.relative_to(PROJECT_ROOT)
                archive_name = Path("securemailscope") / rel_path

                zipf.write(file_path, arcname=str(archive_name))
                print(f"  + Added: {archive_name}")

    file_size_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"[+] Successfully generated: {OUTPUT_ZIP} ({file_size_mb:.2f} MB)")
    return OUTPUT_ZIP


if __name__ == "__main__":
    package_project()
