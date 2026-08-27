import os
import sys
import json
import time
import hashlib
import shutil
import subprocess
from pathlib import Path

import httpx


SERVER = os.getenv("FORENSIC_SERVER", "").rstrip("/")
KEY = os.getenv("CASE_API_KEY", "").strip()

OUT = Path(os.getenv("FORENSIC_AGENT_OUTPUT", "agent_output"))
OUT.mkdir(exist_ok=True)


def adb_exists():
    return shutil.which("adb") is not None


def run_adb(*args):
    try:
        process = subprocess.run(
            ["adb", *args],
            capture_output=True,
            text=True,
            timeout=15
        )

        return {
            "returncode": process.returncode,
            "stdout": process.stdout.strip(),
            "stderr": process.stderr.strip()
        }

    except FileNotFoundError:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "ADB is not installed or is not available in PATH."
        }

    except subprocess.TimeoutExpired:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "ADB command timed out."
        }


def adb_shell(command):
    result = run_adb("shell", command)
    return result["stdout"]


def get_property(name):
    return adb_shell(f"getprop {name}")


def get_devices():
    """
    Return all devices reported by adb devices.

    Possible states:
      device
      unauthorized
      offline
    """

    result = run_adb("devices")

    if result["returncode"] != 0:
        return {
            "adb_available": False,
            "error": result["stderr"] or "ADB failed.",
            "devices": []
        }

    devices = []

    for line in result["stdout"].splitlines():

        line = line.strip()

        if not line or line.lower().startswith("list of devices"):
            continue

        parts = line.split()

        if len(parts) >= 2:

            serial = parts[0]
            state = parts[1]

            devices.append({
                "serial": serial,
                "state": state
            })

    return {
        "adb_available": True,
        "error": None,
        "devices": devices
    }


def device_status():

    status = get_devices()

    if not status["adb_available"]:
        return status

    devices = status["devices"]

    authorized = [
        d for d in devices
        if d["state"] == "device"
    ]

    unauthorized = [
        d for d in devices
        if d["state"] == "unauthorized"
    ]

    offline = [
        d for d in devices
        if d["state"] == "offline"
    ]

    response = {
        "adb_available": True,
        "connected_devices": len(devices),
        "authorized_devices": len(authorized),
        "unauthorized_devices": len(unauthorized),
        "offline_devices": len(offline),
        "devices": devices,
        "error": None
    }

    if authorized:

        serial = authorized[0]["serial"]

        response["device"] = {
            "serial": serial,
            "state": "device",
            "manufacturer": get_property(
                "ro.product.manufacturer"
            ),
            "model": get_property(
                "ro.product.model"
            ),
            "android": get_property(
                "ro.build.version.release"
            ),
            "sdk": get_property(
                "ro.build.version.sdk"
            ),
            "security_patch": get_property(
                "ro.build.version.security_patch"
            ),
            "adb_secure": get_property(
                "ro.adb.secure"
            )
        }

    elif unauthorized:

        response["error"] = (
            "USB debugging authorization is required. "
            "Unlock the phone and accept the RSA authorization dialog."
        )

    elif offline:

        response["error"] = (
            "The Android device is offline. "
            "Reconnect the USB cable and verify USB debugging."
        )

    else:

        response["error"] = (
            "No Android device detected. "
            "Connect a phone with USB debugging enabled."
        )

    return response


def collect_lines(command):

    output = adb_shell(command)

    if not output:
        return []

    return [
        line.strip()
        for line in output.splitlines()
        if line.strip()
    ]


def query_content(uri, projection):

    result = run_adb(
        "shell",
        "content",
        "query",
        "--uri",
        uri,
        "--projection",
        projection
    )

    if result["returncode"] != 0:
        raise RuntimeError(
            result["stderr"] or f"Unable to query {uri}"
        )

    return [
        line
        for line in result["stdout"].splitlines()
        if "Row:" in line
    ]


def apk_sha256(path):

    digest = hashlib.sha256()

    with open(path, "rb") as file:

        for block in iter(
            lambda: file.read(1024 * 1024),
            b""
        ):
            digest.update(block)

    return digest.hexdigest()


def download_apk(package_name):

    result = run_adb(
        "shell",
        "pm",
        "path",
        package_name
    )

    if result["returncode"] != 0:
        return None

    apk_paths = []

    for line in result["stdout"].splitlines():

        line = line.strip()

        if line.startswith("package:"):
            apk_paths.append(
                line.replace("package:", "", 1)
            )

    if not apk_paths:
        return None

    cache = OUT / "apk_cache"
    cache.mkdir(exist_ok=True)

    filename = (
        package_name.replace(".", "_")
        + ".apk"
    )

    destination = cache / filename

    process = subprocess.run(
        [
            "adb",
            "pull",
            apk_paths[0],
            str(destination)
        ],
        capture_output=True,
        text=True,
        timeout=60
    )

    if process.returncode != 0:
        return None

    if not destination.exists():
        return None

    return apk_sha256(destination)


def collect_evidence(serial):

    errors = []

    def safe(function, default):

        try:
            return function()

        except Exception as error:

            errors.append(str(error))

            return default

    contacts = safe(
        lambda: query_content(
            "content://com.android.contacts/data",
            "display_name:data1:mimetype"
        ),
        []
    )

    sms = safe(
        lambda: query_content(
            "content://sms",
            "_id:address:date:type:body"
        ),
        []
    )

    packages = safe(
        lambda: [
            x.replace("package:", "", 1).strip()
            for x in collect_lines("pm list packages -3")
            if x.startswith("package:")
        ],
        []
    )

    running = safe(
        lambda: collect_lines("ps -A"),
        []
    )

    accessibility = safe(
        lambda: collect_lines(
            "settings get secure enabled_accessibility_services"
        ),
        []
    )

    administrators = safe(
        lambda: collect_lines(
            "dumpsys device_policy"
        ),
        []
    )

    network = safe(
        lambda: collect_lines(
            "cat /proc/net/tcp"
        ),
        []
    )

    suspicious_terms = (
        "spy",
        "stealer",
        "keylog",
        "rat",
        "inject",
        "payload",
        "trojan",
        "stalker",
        "remoteadmin"
    )

    suspicious_packages = [
        package
        for package in packages
        if any(
            term in package.lower()
            for term in suspicious_terms
        )
    ]

    findings = []

    if suspicious_packages:

        findings.append({
            "category": "Application triage",
            "severity": "warning",
            "message": (
                "Package-name heuristic match. "
                "Validate application signature, "
                "provenance and APK hash."
            ),
            "packages": suspicious_packages
        })

    if accessibility and accessibility != ["null"]:

        findings.append({
            "category": "Accessibility",
            "severity": "review",
            "message": (
                "Enabled accessibility services "
                "should be reviewed for legitimate purpose."
            ),
            "services": accessibility
        })

    apk_hashes = {}

    for package in packages:

        try:

            digest = download_apk(package)

            if digest:
                apk_hashes[package] = digest

        except Exception as error:

            errors.append(
                f"APK {package}: {error}"
            )

    return {
        "device_id": serial,

        "agent_version": "2.1.0",

        "device": {
            "serial": serial,
            "manufacturer": get_property(
                "ro.product.manufacturer"
            ),
            "model": get_property(
                "ro.product.model"
            ),
            "android": get_property(
                "ro.build.version.release"
            ),
            "sdk": get_property(
                "ro.build.version.sdk"
            ),
            "security_patch": get_property(
                "ro.build.version.security_patch"
            ),
            "fingerprint": get_property(
                "ro.build.fingerprint"
            ),
            "selinux": adb_shell("getenforce"),
            "verified_boot": get_property(
                "ro.boot.verifiedbootstate"
            ),
            "encryption": get_property(
                "ro.crypto.state"
            ),
            "adb_authentication": get_property(
                "ro.adb.secure"
            )
        },

        "contacts": contacts,

        "sms": sms,

        "packages": packages,

        "suspicious_package_flags":
            suspicious_packages,

        "running_processes":
            running,

        "accessibility_services":
            accessibility,

        "device_admins":
            administrators,

        "network_connections":
            network,

        "apk_hashes":
            apk_hashes,

        "findings":
            findings,

        "errors":
            errors
    }


def upload_evidence(evidence):

    if not SERVER:

        raise RuntimeError(
            "FORENSIC_SERVER environment variable is not configured."
        )

    headers = {
        "Content-Type": "application/json"
    }

    if KEY:
        headers["X-API-Key"] = KEY

    response = httpx.post(
        SERVER + "/api/scans",
        json=evidence,
        headers=headers,
        timeout=180
    )

    response.raise_for_status()

    return response.json()


def refresh_command():

    result = device_status()

    print(
        json.dumps(
            result,
            indent=2
        )
    )


def scan_command():

    status = device_status()

    if not status["adb_available"]:
        raise SystemExit(status["error"])

    if status["authorized_devices"] == 0:

        raise SystemExit(
            status["error"]
            or "No authorized Android device."
        )

    device = status["device"]

    serial = device["serial"]

    print(
        f"Starting forensic collection for {serial}..."
    )

    evidence = collect_evidence(serial)

    local_file = (
        OUT /
        (
            "scan_" +
            time.strftime("%Y%m%d_%H%M%S") +
            ".json"
        )
    )

    local_file.write_text(
        json.dumps(
            evidence,
            indent=2
        ),
        encoding="utf-8"
    )

    print(
        f"Local evidence saved: {local_file}"
    )

    result = upload_evidence(evidence)

    print(
        json.dumps(
            result,
            indent=2
        )
    )

    print()
    print("Contacts:", len(evidence["contacts"]))
    print("SMS:", len(evidence["sms"]))
    print("Applications:", len(evidence["packages"]))
    print(
        "Running processes:",
        len(evidence["running_processes"])
    )
    print(
        "Suspicious package indicators:",
        len(evidence["suspicious_package_flags"])
    )


def main():

    if len(sys.argv) > 1:

        command = sys.argv[1].lower()

    else:

        command = "scan"

    if not adb_exists():

        print(
            "ERROR: ADB is not installed or is not in PATH."
        )

        print(
            "Install Android Platform Tools and add adb to PATH."
        )

        sys.exit(1)

    if command == "refresh":

        refresh_command()

    elif command == "scan":

        scan_command()

    else:

        print(
            "Usage:"
        )

        print(
            "  python agent.py refresh"
        )

        print(
            "  python agent.py scan"
        )

        sys.exit(1)


if __name__ == "__main__":
    main()
