#!/usr/bin/env python3
"""
PyInstaller build script for KiroProManager.
"""
import os
import sys
import shutil
import subprocess
import site
from pathlib import Path

PROJECT_DIR = Path(__file__).parent
MAIN_PY = PROJECT_DIR / "main.py"
DIST_DIR = PROJECT_DIR / "dist" / "KiroProManager"
SPEC_FILE = PROJECT_DIR / "KiroProManager.spec"

site_packages = Path(site.getsitepackages()[1])
browsers_dir = Path.home() / "AppData" / "Local" / "ms-playwright"

# Find playwright driver and stealth paths
playwright_driver = site_packages / "playwright" / "driver"
playwright_stealth = site_packages / "playwright_stealth"

# Find chromium browser
chromium_dir = None
for d in sorted(browsers_dir.glob("chromium-*"), reverse=True):
    if d.is_dir():
        chromium_dir = d
        break

chromium_headless_dir = None
for d in sorted(browsers_dir.glob("chromium_headless_shell-*"), reverse=True):
    if d.is_dir():
        chromium_headless_dir = d
        break

print(f"[*] Project: {PROJECT_DIR}")
print(f"[*] Site-packages: {site_packages}")
print(f"[*] Playwright driver: {playwright_driver}")
print(f"[*] Playwright stealth: {playwright_stealth}")
print(f"[*] Chromium: {chromium_dir}")
print(f"[*] Chromium headless: {chromium_headless_dir}")
print()

# Build datas list for --add-data
datas = []
if playwright_driver.exists():
    datas.append(f"--add-data={playwright_driver}{os.pathsep}playwright/driver")
if playwright_stealth.exists():
    datas.append(f"--add-data={playwright_stealth}{os.pathsep}playwright_stealth")
if chromium_dir:
    datas.append(f"--add-data={chromium_dir}{os.pathsep}ms-playwright/{chromium_dir.name}")
if chromium_headless_dir:
    datas.append(f"--add-data={chromium_headless_dir}{os.pathsep}ms-playwright/{chromium_headless_dir.name}")

# Include mail_providers package
mail_providers_dir = PROJECT_DIR / "mail_providers"
if mail_providers_dir.exists():
    datas.append(f"--add-data={mail_providers_dir}{os.pathsep}mail_providers")

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--noconfirm",
    "--name=KiroProManager",
    "--windowed",
    f"--distpath={PROJECT_DIR / 'dist'}",
    f"--workpath={PROJECT_DIR / 'build_tmp'}",
    f"--specpath={PROJECT_DIR}",
    # Hidden imports
    "--hidden-import=curl_cffi",
    "--hidden-import=curl_cffi.requests",
    "--hidden-import=playwright",
    "--hidden-import=playwright.async_api",
    "--hidden-import=playwright_stealth",
    "--hidden-import=cryptography",
    "--hidden-import=cffi",
    "--hidden-import=_cffi_backend",
    "--hidden-import=tkinter",
    "--hidden-import=tkinter.ttk",
    "--hidden-import=tkinter.messagebox",
    "--hidden-import=tkinter.filedialog",
    "--hidden-import=json",
    "--hidden-import=sqlite3",
    "--hidden-import=concurrent.futures",
    "--hidden-import=kiro_register",
    "--hidden-import=kiro_subscribe",
    "--hidden-import=kiro_login",
    "--hidden-import=stripe_pay",
    "--hidden-import=captcha_solver",
    "--hidden-import=mail_providers",
    "--hidden-import=mail_providers.base",
    "--hidden-import=mail_providers.shiromail",
    # Collect all from curl_cffi (has native libs)
    "--collect-all=curl_cffi",
    # Data files
    *datas,
    # Main script
    str(MAIN_PY),
]

print("[*] Building with PyInstaller...")
print(f"[*] Command: {' '.join(cmd[:8])}...")
print()

result = subprocess.run(cmd, cwd=str(PROJECT_DIR))

if result.returncode != 0:
    print(f"\n[!] Build failed with code {result.returncode}")
    sys.exit(1)

# Clean up build temp
build_tmp = PROJECT_DIR / "build_tmp"
if build_tmp.exists():
    shutil.rmtree(build_tmp, ignore_errors=True)

print(f"\n[+] Build complete: {DIST_DIR / 'KiroProManager.exe'}")
