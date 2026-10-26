"""Build the finished, ready-to-share Packet Sniffer.

    python tools/build.py              all four steps
    python tools/build.py dashboard    steps 1-2 only (run after editing static/app.jsx)

1. React and ReactDOM are kept in static/vendor/, so the dashboard works
   without internet and its security policy can allow this server's scripts only.
2. static/app.jsx is compiled to plain JavaScript (static/app.js) by Babel,
   run in Node, so the browser no longer downloads a 3 MB compiler at start.
3. PyInstaller turns sniffer.py into dist/PacketSniffer/PacketSniffer.exe, with
   Python, Flask, Scapy and the dashboard inside. Windows still needs Npcap.
4. Two zips are made in dist/:
       PacketSniffer-<version>-windows.zip   the program, both sample captures, README
       packet-sniffer-<version>-source.zip   the source code of the current commit

Every downloaded file is checked against a pinned SHA-256 hash.
Needs Node.js (step 2), "pip install pyinstaller" (step 3) and git (step 4).
"""

import hashlib
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from core import __version__  # noqa: E402

CDN = "https://cdnjs.cloudflare.com/ajax/libs"
VENDOR = {
    "static/vendor/react.production.min.js": (
        f"{CDN}/react/18.3.1/umd/react.production.min.js",
        "d949f1c3687aedadcedac85261865f29b17cd273997e7f6b2bfc53b2f9d4c4dd"),
    "static/vendor/react-dom.production.min.js": (
        f"{CDN}/react-dom/18.3.1/umd/react-dom.production.min.js",
        "35f4f974f4b2bcd44da73963347f8952e341f83909e4498227d4e26b98f66f0d"),
}
BABEL = ("build/cache/babel.min.js", f"{CDN}/babel-standalone/7.26.4/babel.min.js",
         "a12872ea8da3d29b2a296c51bfac7c482e81419c755f2207a49ad9b77200f4ea")

# Big libraries that Scapy can use if installed (plots, TLS decryption, notebooks)
# but the sniffer never needs; leaving them out makes the program about 5x smaller.
EXCLUDE = [
    "boto3", "botocore", "contourpy", "cryptography", "IPython", "lxml", "matplotlib",
    "numpy", "pandas", "PIL", "pytest", "sqlalchemy", "tkinter", "tzdata", "yaml",
]

APP_SOURCE = "static/app.jsx"
APP_BUILT = "static/app.js"

COMPILE_JS = """
const fs = require("fs");
const [babelPath, source, target] = process.argv.slice(2);
const Babel = require(babelPath);
const code = fs.readFileSync(source, "utf8");
const result = Babel.transform(code, { presets: ["react"], filename: "app.jsx", comments: false });
fs.writeFileSync(target, result.code);
"""

HOW_TO_RUN = f"""Packet Sniffer {__version__}
====================

1. Install Npcap from https://npcap.com (keep the default options).
   Windows cannot capture packets without it.

2. Double-click PacketSniffer.exe. It starts capturing on the default
   network interface and opens the dashboard in your browser, already
   unlocked. The access code is also printed in the black window.

3. Close the black window (or press Ctrl+C in it) to stop.

One-click security fixes (blocking an attacker in Windows Firewall) need
Administrator rights: right-click PacketSniffer.exe, Run as administrator.

Demo without capturing (open a terminal in this folder):

    PacketSniffer.exe --pcap samples\\sample_traffic.pcap --loop
    PacketSniffer.exe --pcap samples\\attack_traffic.pcap

All options:  PacketSniffer.exe --help
More detail:  README.md

Capture only on your own device and network.
"""


def path(relative):
    return os.path.join(ROOT, relative)


def sha256(file):
    with open(file, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def source_hash(file):
    """Hash of a text file that ignores Windows/Unix line endings (git may convert them)."""
    with open(file, "rb") as f:
        return hashlib.sha256(f.read().replace(b"\r\n", b"\n")).hexdigest()


def fetch(relative, url, expected):
    """Download ``url`` to ``relative`` unless an identical copy is already there."""
    target = path(relative)
    if os.path.exists(target) and sha256(target) == expected:
        return
    os.makedirs(os.path.dirname(target), exist_ok=True)
    print(f"  downloading {url}")
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        sys.exit(f"Refusing {url}: SHA-256 is {actual}, expected {expected}")
    with open(target, "wb") as f:
        f.write(data)


def build_dashboard():
    print("1. React for offline use")
    for relative, (url, expected) in VENDOR.items():
        fetch(relative, url, expected)

    print("2. Compiling static/app.jsx")
    fetch(*BABEL)
    if not shutil.which("node"):
        sys.exit("Node.js is needed to compile the dashboard: https://nodejs.org")
    compiler = path("build/cache/compile.js")
    with open(compiler, "w", encoding="utf-8") as f:
        f.write(COMPILE_JS)
    compiled = path("build/cache/app.js")
    subprocess.run(["node", compiler, path(BABEL[0]), path(APP_SOURCE), compiled], check=True)
    with open(compiled, encoding="utf-8") as f:
        code = f.read()
    header = (f"// Built by tools/build.py from static/app.jsx (sha256 {source_hash(path(APP_SOURCE))}).\n"
              "// Do not edit: change app.jsx, then run  python tools/build.py dashboard\n")
    with open(path(APP_BUILT), "w", encoding="utf-8", newline="\n") as f:
        f.write(header + code + "\n")
    print(f"  wrote {APP_BUILT}")


def build_exe():
    print("3. Building PacketSniffer.exe")
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        sys.exit('PyInstaller is needed: pip install pyinstaller')
    subprocess.run([
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--log-level", "WARN",
        "--name", "PacketSniffer", "--console",
        "--distpath", path("dist"), "--workpath", path("build/pyinstaller"), "--specpath", path("build"),
        "--add-data", f"{path('static')}{os.pathsep}static",
        "--add-data", f"{path('core/blocklist.txt')}{os.pathsep}core",
        *[arg for module in EXCLUDE for arg in ("--exclude-module", module)],
        path("sniffer.py"),
    ], check=True, cwd=ROOT)
    folder = path("dist/PacketSniffer")
    shutil.copytree(path("samples"), os.path.join(folder, "samples"), dirs_exist_ok=True)
    shutil.copy(path("README.md"), folder)
    with open(os.path.join(folder, "HOW TO RUN.txt"), "w", encoding="utf-8", newline="\r\n") as f:
        f.write(HOW_TO_RUN)


def zip_folder(folder, target):
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for base, _dirs, files in os.walk(folder):
            for name in files:
                full = os.path.join(base, name)
                z.write(full, os.path.relpath(full, os.path.dirname(folder)))


def package():
    print("4. Packaging")
    windows = path(f"dist/PacketSniffer-{__version__}-windows.zip")
    zip_folder(path("dist/PacketSniffer"), windows)
    source = path(f"dist/packet-sniffer-{__version__}-source.zip")
    subprocess.run(["git", "archive", "--format=zip", "--prefix=packet-sniffer/", "-o", source, "HEAD"],
                   check=True, cwd=ROOT)
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True, cwd=ROOT).stdout.strip()
    if dirty:
        print("  note: the source zip has the last commit; uncommitted changes are not in it")
    for zipped in (windows, source):
        print(f"  {os.path.relpath(zipped, ROOT)}  {os.path.getsize(zipped) / 1024 / 1024:.1f} MB")


def main():
    step = sys.argv[1] if len(sys.argv) > 1 else "all"
    if step not in ("all", "dashboard"):
        sys.exit(__doc__)
    build_dashboard()
    if step == "all":
        build_exe()
        package()
    print("Done.")


if __name__ == "__main__":
    main()
