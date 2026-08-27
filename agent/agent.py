import os
import sys
import json
import time
import hashlib
import shutil
import subprocess
from pathlib import Path

import httpx


# ============================================================
# CONFIGURATION
# ============================================================

SERVER = os.getenv(
    "FORENSIC_SERVER",
    ""
).rstrip("/")

CASE_API_KEY = os.getenv(
    "CASE_API_KEY",
    ""
).strip()

OUTPUT_DIR = Path(
    os.getenv(
        "FORENSIC_AGENT_OUTPUT",
        "agent_output"
    )
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# ADB BASIC FUNCTIONS
# ============================================================

def adb_exists():
    """
    Check whether adb exists in PATH.
    """

    return shutil.which("adb") is not None


def run_adb(*args, timeout=30):
    """
    Execute an ADB command safely.
    """

    try:

        result = subprocess.run(
            [
                "adb",
                *args
            ],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip()
        }

    except FileNotFoundError:

        return {
            "returncode": -1,
            "stdout": "",
            "stderr": (
                "ADB is not installed "
                "or is not available in PATH."
            )
        }

    except subprocess.TimeoutExpired:

        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "ADB command timed out."
        }

    except Exception as error:

        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(error)
        }


def adb_shell(command, timeout=30):
    """
    Execute a shell command on Android.
    """

    result = run_adb(
        "shell",
        command,
        timeout=timeout
    )

    return result["stdout"]


# ============================================================
# DEVICE PROPERTIES
# ============================================================

def get_property(name):

    return adb_shell(
        f"getprop {name}"
    )


# ============================================================
# GET ALL ADB DEVICES
# ============================================================

def get_devices():

    result = run_adb(
        "devices"
    )

    if result["returncode"] != 0:

        return {
            "adb_available": False,
            "error": (
                result["stderr"]
                or "ADB failed."
            ),
            "devices": []
        }

    devices = []

    for line in result["stdout"].splitlines():

        line = line.strip()

        if not line:
            continue

        if line.lower().startswith(
            "list of devices"
        ):
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


# ============================================================
# COMPLETE ADB STATUS
# ============================================================

def device_status():

    status = get_devices()

    if not status["adb_available"]:

        return status

    devices = status["devices"]

    authorized = [
        device
        for device in devices
        if device["state"] == "device"
    ]

    unauthorized = [
        device
        for device in devices
        if device["state"] == "unauthorized"
    ]

    offline = [
        device
        for device in devices
        if device["state"] == "offline"
    ]

    response = {

        "adb_available": True,

        "connected_devices":
            len(devices),

        "authorized_devices":
            len(authorized),

        "unauthorized_devices":
            len(unauthorized),

        "offline_devices":
            len(offline),

        "devices":
            devices,

        "error":
            None
    }

    # --------------------------------------------------------
    # AUTHORIZED DEVICE
    # --------------------------------------------------------

    if authorized:

        device = authorized[0]

        serial = device["serial"]

        response["device"] = {

            "serial":
                serial,

            "state":
                "device",

            "manufacturer":
                get_property(
                    "ro.product.manufacturer"
                ),

            "model":
                get_property(
                    "ro.product.model"
                ),

            "android":
                get_property(
                    "ro.build.version.release"
                ),

            "sdk":
                get_property(
                    "ro.build.version.sdk"
                ),

            "security_patch":
                get_property(
                    "ro.build.version.security_patch"
                ),

            "fingerprint":
                get_property(
                    "ro.build.fingerprint"
                ),

            "adb_secure":
                get_property(
                    "ro.adb.secure"
                )
        }

        return response

    # --------------------------------------------------------
    # UNAUTHORIZED DEVICE
    # --------------------------------------------------------

    if unauthorized:

        response["error"] = (
            "USB debugging authorization is required. "
            "Unlock the Android phone and accept "
            "the RSA authorization dialog."
        )

        return response

    # --------------------------------------------------------
    # OFFLINE DEVICE
    # --------------------------------------------------------

    if offline:

        response["error"] = (
            "The Android device is offline. "
            "Reconnect the USB cable and verify "
            "USB debugging."
        )

        return response

    # --------------------------------------------------------
    # NO DEVICE
    # --------------------------------------------------------

    response["error"] = (
        "No Android device detected. "
        "Connect the phone and enable USB debugging."
    )

    return response


# ============================================================
# GENERIC SHELL OUTPUT
# ============================================================

def collect_lines(command):

    output = adb_shell(
        command
    )

    if not output:
        return []

    return [
        line.strip()
        for line in output.splitlines()
        if line.strip()
    ]


# ============================================================
# CONTENT PROVIDER QUERY
# ============================================================

def query_content(
    uri,
    projection
):

    result = run_adb(
        "shell",
        "content",
        "query",
        "--uri",
        uri,
        "--projection",
        projection,
        timeout=60
    )

    if result["returncode"] != 0:

        raise RuntimeError(
            result["stderr"]
            or f"Unable to query {uri}"
        )

    return [
        line
        for line in result["stdout"].splitlines()
        if "Row:" in line
    ]


# ============================================================
# SHA256
# ============================================================

def sha256_file(path):

    digest = hashlib.sha256()

    with open(
        path,
        "rb"
    ) as file:

        for block in iter(
            lambda:
                file.read(1024 * 1024),
            b""
        ):

            digest.update(
                block
            )

    return digest.hexdigest()


# ============================================================
# DOWNLOAD APK FOR HASHING
# ============================================================

def download_apk(package_name):

    result = run_adb(
        "shell",
        "pm",
        "path",
        package_name,
        timeout=30
    )

    if result["returncode"] != 0:
        return None

    paths = []

    for line in result["stdout"].splitlines():

        line = line.strip()

        if line.startswith(
            "package:"
        ):

            paths.append(
                line.replace(
                    "package:",
                    "",
                    1
                )
            )

    if not paths:
        return None

    cache_dir = (
        OUTPUT_DIR /
        "apk_cache"
    )

    cache_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    filename = (
        package_name.replace(
            ".",
            "_"
        )
        + ".apk"
    )

    destination = (
        cache_dir /
        filename
    )

    try:

        result = subprocess.run(
            [
                "adb",
                "pull",
                paths[0],
                str(destination)
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return None

        if not destination.exists():
            return None

        return sha256_file(
            destination
        )

    except Exception:

        return None


# ============================================================
# EVIDENCE COLLECTION
# ============================================================

def collect_evidence(serial):

    errors = []

    def safe(
        function,
        default
    ):

        try:

            return function()

        except Exception as error:

            errors.append(
                str(error)
            )

            return default

    # --------------------------------------------------------
    # CONTACTS
    # --------------------------------------------------------

    contacts = safe(
        lambda:
            query_content(
                "content://com.android.contacts/data",
                "display_name:data1:mimetype"
            ),
        []
    )

    # --------------------------------------------------------
    # SMS
    # --------------------------------------------------------

    sms = safe(
        lambda:
            query_content(
                "content://sms",
                "_id:address:date:type:body"
            ),
        []
    )

    # --------------------------------------------------------
    # THIRD-PARTY PACKAGES
    # --------------------------------------------------------

    packages = safe(
        lambda: [
            item.replace(
                "package:",
                "",
                1
            ).strip()

            for item in
            collect_lines(
                "pm list packages -3"
            )

            if item.startswith(
                "package:"
            )
        ],
        []
    )

    # --------------------------------------------------------
    # RUNNING PROCESSES
    # --------------------------------------------------------

    running_processes = safe(
        lambda:
            collect_lines(
                "ps -A"
            ),
        []
    )

    # --------------------------------------------------------
    # ACCESSIBILITY
    # --------------------------------------------------------

    accessibility = safe(
        lambda:
            collect_lines(
                "settings get secure "
                "enabled_accessibility_services"
            ),
        []
    )

    # --------------------------------------------------------
    # DEVICE ADMIN
    # --------------------------------------------------------

    device_admins = safe(
        lambda:
            collect_lines(
                "dumpsys device_policy"
            ),
        []
    )

    # --------------------------------------------------------
    # NETWORK
    # --------------------------------------------------------

    network = safe(
        lambda:
            collect_lines(
                "cat /proc/net/tcp"
            ),
        []
    )

    # --------------------------------------------------------
    # PACKAGE NAME TRIAGE
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # FINDINGS
    # --------------------------------------------------------

    findings = []

    if suspicious_packages:

        findings.append({

            "category":
                "Application triage",

            "severity":
                "warning",

            "message":
                (
                    "Package-name heuristic match. "
                    "Validate application signature, "
                    "provenance and APK hash."
                ),

            "packages":
                suspicious_packages
        })

    if (
        accessibility
        and
        accessibility != ["null"]
    ):

        findings.append({

            "category":
                "Accessibility",

            "severity":
                "review",

            "message":
                (
                    "Enabled accessibility services "
                    "should be reviewed for legitimate use."
                ),

            "services":
                accessibility
        })

    if device_admins:

        findings.append({

            "category":
                "Device administration",

            "severity":
                "review",

            "message":
                (
                    "Device administrator entries "
                    "should be reviewed."
                ),

            "records":
                device_admins
        })

    # --------------------------------------------------------
    # APK HASHES
    # --------------------------------------------------------

    apk_hashes = {}

    for package in packages:

        try:

            digest = download_apk(
                package
            )

            if digest:

                apk_hashes[
                    package
                ] = digest

        except Exception as error:

            errors.append(
                f"APK {package}: {error}"
            )

    # --------------------------------------------------------
    # FINAL EVIDENCE
    # --------------------------------------------------------

    evidence = {

        "device_id":
            serial,

        "agent_version":
            "2.1.0",

        "device": {

            "serial":
                serial,

            "manufacturer":
                get_property(
                    "ro.product.manufacturer"
                ),

            "model":
                get_property(
                    "ro.product.model"
                ),

            "android":
                get_property(
                    "ro.build.version.release"
                ),

            "sdk":
                get_property(
                    "ro.build.version.sdk"
                ),

            "security_patch":
                get_property(
                    "ro.build.version.security_patch"
                ),

            "fingerprint":
                get_property(
                    "ro.build.fingerprint"
                ),

            "selinux":
                adb_shell(
                    "getenforce"
                ),

            "verified_boot":
                get_property(
                    "ro.boot.verifiedbootstate"
                ),

            "encryption":
                get_property(
                    "ro.crypto.state"
                ),

            "adb_authentication":
                get_property(
                    "ro.adb.secure"
                )
        },

        "contacts":
            contacts,

        "sms":
            sms,

        "packages":
            packages,

        "suspicious_package_flags":
            suspicious_packages,

        "running_processes":
            running_processes,

        "accessibility_services":
            accessibility,

        "device_admins":
            device_admins,

        "network_connections":
            network,

        "apk_hashes":
            apk_hashes,

        "findings":
            findings,

        "errors":
            errors
    }

    return evidence


# ============================================================
# UPLOAD EVIDENCE TO RENDER
# ============================================================

def upload_evidence(evidence):

    if not SERVER:

        raise RuntimeError(
            "FORENSIC_SERVER is not configured."
        )

    headers = {
        "Content-Type":
            "application/json"
    }

    if CASE_API_KEY:

        headers[
            "X-API-Key"
        ] = CASE_API_KEY

    response = httpx.post(

        SERVER +
        "/api/scans",

        json=evidence,

        headers=headers,

        timeout=180
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# REFRESH COMMAND
# ============================================================

def refresh_command():

    result = device_status()

    print(
        json.dumps(
            result,
            indent=2
        )
    )


# ============================================================
# SCAN COMMAND
# ============================================================

def scan_command():

    status = device_status()

    if not status[
        "adb_available"
    ]:

        raise SystemExit(
            status["error"]
        )

    if status[
        "authorized_devices"
    ] == 0:

        raise SystemExit(
            status["error"]
            or
            "No authorized Android device."
        )

    device = status[
        "device"
    ]

    serial = device[
        "serial"
    ]

    print(
        "Starting forensic "
        f"collection for {serial}..."
    )

    evidence = collect_evidence(
        serial
    )

    filename = (
        "scan_"
        +
        time.strftime(
            "%Y%m%d_%H%M%S"
        )
        +
        ".json"
    )

    local_file = (
        OUTPUT_DIR /
        filename
    )

    local_file.write_text(
        json.dumps(
            evidence,
            indent=2
        ),
        encoding="utf-8"
    )

    print(
        "Local evidence saved:"
    )

    print(
        local_file
    )

    result = upload_evidence(
        evidence
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )

    print()
    print(
        "Contacts:",
        len(
            evidence["contacts"]
        )
    )

    print(
        "SMS:",
        len(
            evidence["sms"]
        )
    )

    print(
        "Applications:",
        len(
            evidence["packages"]
        )
    )

    print(
        "Running processes:",
        len(
            evidence[
                "running_processes"
            ]
        )
    )

    print(
        "Suspicious indicators:",
        len(
            evidence[
                "suspicious_package_flags"
            ]
        )
    )


# ============================================================
# MAIN
# ============================================================

def main():

    command = (
        sys.argv[1].lower()
        if len(sys.argv) > 1
        else "scan"
    )

    if not adb_exists():

        print(
            "ERROR: ADB is not installed "
            "or is not available in PATH."
        )

        print()
        print(
            "Install Android Platform Tools "
            "and add adb to PATH."
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
            "python agent.py refresh"
        )

        print(
            "python agent.py scan"
        )

        sys.exit(1)


if __name__ == "__main__":

    main()
