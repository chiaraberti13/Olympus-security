#!/usr/bin/env python3
"""
Utility to validate the project file set and provide manual setup guidance.
This script does not generate application code; it reports missing or empty files
and writes a manual setup guide to help users restore the project structure.
"""

from pathlib import Path

print("🚀 Validating project files and generating manual setup guide...")
print("=" * 60)

required_files = [
    "app.py",
    "config.py",
    "database.py",
    "scanner_engine.py",
    "report_generator.py",
    "requirements.txt",
    "templates/index.html",
    "templates/scan_detail.html",
    "templates/scans_list.html",
    "scanners/__init__.py",
    "scanners/nuclei_scanner.py",
    "scanners/nmap_scanner.py",
    "scanners/whatweb_scanner.py",
    "scanners/subfinder_scanner.py",
    "scanners/nikto_scanner.py",
]

missing_or_empty = []
for file_name in required_files:
    file_path = Path(file_name)
    if not file_path.exists():
        missing_or_empty.append(f"{file_name} (missing)")
    elif file_path.stat().st_size == 0:
        missing_or_empty.append(f"{file_name} (empty)")

if missing_or_empty:
    print("⚠️  Missing or incomplete files detected:")
    for item in missing_or_empty:
        print(f"   - {item}")
else:
    print("✅ All required files are present and non-empty.")

instructions = """
MANUAL SETUP INSTRUCTIONS
=========================

If any required files are missing or empty, restore them from your source
archive or repository before running the installer.

To complete the manual installation:

1. Restore the required Python files:
   - config.py
   - database.py
   - scanner_engine.py
   - report_generator.py
   - app.py
   - scanners/__init__.py
   - scanners/nuclei_scanner.py
   - scanners/nmap_scanner.py
   - scanners/whatweb_scanner.py
   - scanners/subfinder_scanner.py
   - scanners/nikto_scanner.py

2. Restore the HTML templates:
   - templates/index.html
   - templates/scan_detail.html
   - templates/scans_list.html

3. Run the installer:
   ./installer.sh

On Windows, use:
   powershell -ExecutionPolicy Bypass -File installer.ps1
"""

with open("MANUAL_SETUP_INSTRUCTIONS.txt", "w") as f:
    f.write(instructions)

print("✓ Manual setup guide written to: MANUAL_SETUP_INSTRUCTIONS.txt")
