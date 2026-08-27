
"""
Smart Cyber Forensic ADB Agent
--------------------------------

Runs LOCALLY on the Windows/Linux computer connected to an Android device.

Features:
- Real ADB device detection
- Device properties
- Installed package enumeration
- Package metadata / permissions
- Running process enumeration
- Services/components where Android permits access
- Network information
- Contacts acquisition when the connected Android build permits it
- SMS acquisition when the connected Android build permits it
- Transparent suspicious-indicator rules
- No fabricated counts
- JSON forensic export
- ZIP forensic export
- SHA-256 hashes for exported evidence files

IMPORTANT:
This is an acquisition/analysis agent, not an antivirus engine.
"Suspicious" means an indicator matched a rule. It is NOT proof of malware.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

import subprocess
import shutil
import platform
import json
import hashlib
import os
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Any, Optional


# ============================================================
# CONFIGURATION
# ============================================================

HOST = "127.0.0.1"
PORT = 8765

EXPORT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "exports"
)

os.makedirs(EXPORT_DIR, exist_ok=True)


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="Smart Cyber Forensic ADB Agent",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://ai-cyber-attack-detection-nfzw.onrender.com",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "null",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# GENERAL HELPERS
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str) -> str:

    h = hashlib.sha256()

    with open(path, "rb") as f:

        while True:

            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


def adb_executable() -> Optional[str]:

    return shutil.which("adb")


def execute(
    command: list[str],
    timeout: int = 30
) -> dict[str, Any]:

    try:

        creationflags = 0

        if platform.system() == "Windows":

            creationflags = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=creationflags
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "ok": result.returncode == 0
        }

    except subprocess.TimeoutExpired:

        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Command timed out.",
            "ok": False
        }

    except Exception as exc:

        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "ok": False
        }


def run_adb(
    args: list[str],
    timeout: int = 30
) -> dict[str, Any]:

    adb = adb_executable()

    if not adb:

        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "ADB executable was not found in PATH.",
            "ok": False
        }

    return execute(
        [adb] + args,
        timeout=timeout
    )


def run_shell(
    serial: str,
    command: str,
    timeout: int = 30
) -> dict[str, Any]:

    return run_adb(
        [
            "-s",
            serial,
            "shell",
            command
        ],
        timeout=timeout
    )


# ============================================================
# DEVICE DETECTION
# ============================================================

def get_devices() -> list[dict[str, Any]]:

    result = run_adb(
        ["devices", "-l"]
    )

    if not result["ok"]:
        return []

    devices = []

    for raw_line in result["stdout"].splitlines():

        line = raw_line.strip()

        if not line:
            continue

        if line.lower().startswith("list of devices"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        serial = parts[0]
        state = parts[1]

        device = {
            "serial": serial,
            "state": state,
            "transport_id": None,
            "product": None,
            "model": None,
            "device": None
        }

        for part in parts[2:]:

            if ":" not in part:
                continue

            key, value = part.split(
                ":",
                1
            )

            if key == "transport_id":
                device["transport_id"] = value

            elif key == "product":
                device["product"] = value

            elif key == "model":
                device["model"] = value

            elif key == "device":
                device["device"] = value

        devices.append(device)

    return devices


def get_property(
    serial: str,
    name: str
) -> Optional[str]:

    result = run_shell(
        serial,
        f"getprop {name}"
    )

    if not result["ok"]:
        return None

    value = result["stdout"].strip()

    return value if value else None


def get_device_info(
    serial: str
) -> dict[str, Any]:

    properties = {
        "manufacturer":
            get_property(
                serial,
                "ro.product.manufacturer"
            ),

        "brand":
            get_property(
                serial,
                "ro.product.brand"
            ),

        "model":
            get_property(
                serial,
                "ro.product.model"
            ),

        "device":
            get_property(
                serial,
                "ro.product.device"
            ),

        "android_version":
            get_property(
                serial,
                "ro.build.version.release"
            ),

        "sdk":
            get_property(
                serial,
                "ro.build.version.sdk"
            ),

        "security_patch":
            get_property(
                serial,
                "ro.build.version.security_patch"
            ),

        "build":
            get_property(
                serial,
                "ro.build.display.id"
            ),

        "fingerprint":
            get_property(
                serial,
                "ro.build.fingerprint"
            )
    }

    return {
        "serial": serial,
        **properties
    }


# ============================================================
# PACKAGES
# ============================================================

def get_packages(
    serial: str
) -> list[dict[str, Any]]:

    result = run_shell(
        serial,
        "pm list packages -f -U",
        timeout=60
    )

    if not result["ok"]:
        return []

    packages = []

    for line in result["stdout"].splitlines():

        line = line.strip()

        if not line.startswith("package:"):
            continue

        # Example:
        # package:/data/app/.../base.apk=com.example.app uid:10123

        text = line[len("package:"):]

        uid = None

        uid_match = re.search(
            r"\s+uid:(\d+)",
            text
        )

        if uid_match:

            uid = int(
                uid_match.group(1)
            )

            text = text[
                :uid_match.start()
            ]

        if "=" not in text:
            continue

        apk_path, package_name = text.rsplit(
            "=",
            1
        )

        packages.append(
            {
                "package": package_name.strip(),
                "apk_path": apk_path.strip(),
                "uid": uid
            }
        )

    return packages


def get_package_permissions(
    serial: str,
    package_name: str
) -> list[str]:

    result = run_shell(
        serial,
        f"dumpsys package {package_name}",
        timeout=30
    )

    if not result["ok"]:
        return []

    permissions = set()

    for line in result["stdout"].splitlines():

        match = re.search(
            r"(android\.permission\.[A-Z0-9_]+)",
            line
        )

        if match:

            permissions.add(
                match.group(1)
            )

    return sorted(permissions)


# ============================================================
# PROCESSES
# ============================================================

def get_processes(
    serial: str
) -> list[dict[str, Any]]:

    result = run_shell(
        serial,
        "ps -A",
        timeout=60
    )

    if not result["ok"]:
        return []

    lines = result["stdout"].splitlines()

    if not lines:
        return []

    processes = []

    header = lines[0]

    # Attempt to identify column indexes.
    header_parts = header.split()

    for line in lines[1:]:

        parts = line.split()

        if len(parts) < 4:
            continue

        record = {
            "raw": line
        }

        if len(parts) >= 9:

            record["user"] = parts[0]
            record["pid"] = parts[1]
            record["ppid"] = parts[2]

            record["name"] = parts[-1]

        else:

            record["name"] = parts[-1]

        processes.append(record)

    return processes


# ============================================================
# SERVICES / COMPONENTS
# ============================================================

def get_services(
    serial: str
) -> dict[str, Any]:

    result = run_shell(
        serial,
        "dumpsys activity services",
        timeout=60
    )

    if not result["ok"]:

        return {
            "available": False,
            "services": [],
            "error": result["stderr"]
        }

    services = []

    seen = set()

    for line in result["stdout"].splitlines():

        line = line.strip()

        if not line:
            continue

        # Android output varies by version.
        # Extract component-like names when present.

        matches = re.findall(
            r"[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+",
            line
        )

        for match in matches:

            if match in seen:
                continue

            seen.add(match)

            services.append(
                {
                    "component": match,
                    "raw": line
                }
            )

    return {
        "available": True,
        "services": services
    }


def get_components(
    serial: str
) -> dict[str, Any]:

    result = run_shell(
        serial,
        "dumpsys package",
        timeout=90
    )

    if not result["ok"]:

        return {
            "available": False,
            "components": [],
            "error": result["stderr"]
        }

    components = []

    patterns = [
        "Service",
        "Receiver",
        "Activity",
        "Provider"
    ]

    for line in result["stdout"].splitlines():

        stripped = line.strip()

        if not stripped:
            continue

        if any(
            p in stripped
            for p in patterns
        ):

            components.append(
                {
                    "raw": stripped
                }
            )

    return {
        "available": True,
        "components": components
    }


# ============================================================
# NETWORK
# ============================================================

def get_network(
    serial: str
) -> dict[str, Any]:

    ip_result = run_shell(
        serial,
        "ip addr",
        timeout=30
    )

    route_result = run_shell(
        serial,
        "ip route",
        timeout=30
    )

    dns_result = run_shell(
        serial,
        "getprop | grep dns",
        timeout=30
    )

    connections_result = run_shell(
        serial,
        "cat /proc/net/tcp",
        timeout=30
    )

    return {
        "ip_addr": (
            ip_result["stdout"]
            if ip_result["ok"]
            else None
        ),

        "routes": (
            route_result["stdout"]
            if route_result["ok"]
            else None
        ),

        "dns": (
            dns_result["stdout"]
            if dns_result["ok"]
            else None
        ),

        "tcp": (
            connections_result["stdout"]
            if connections_result["ok"]
            else None
        )
    }


# ============================================================
# CONTACTS
# ============================================================

def get_contacts(
    serial: str
) -> dict[str, Any]:

    """
    Attempts acquisition through the Android Contacts provider.

    Android/OEM/version restrictions may deny this operation.
    In that case we explicitly return unavailable=True rather
    than inventing a count.
    """

    commands = [
        (
            "content query "
            "--uri content://com.android.contacts/data/phones "
            "--projection display_name:data1:contact_id"
        ),
        (
            "content query "
            "--uri content://contacts/phones "
            "--projection display_name:number"
        )
    ]

    last_error = None

    for command in commands:

        result = run_shell(
            serial,
            command,
            timeout=60
        )

        if not result["ok"]:

            last_error = result["stderr"]
            continue

        output = result["stdout"].strip()

        if not output:
            continue

        items = []

        for line in output.splitlines():

            if not line.strip():
                continue

            item = {
                "raw": line
            }

            name_match = re.search(
                r"display_name=([^,]+)",
                line
            )

            number_match = re.search(
                r"(?:data1|number)=([^,]+)",
                line
            )

            contact_match = re.search(
                r"contact_id=([^,]+)",
                line
            )

            if name_match:
                item["name"] = name_match.group(1).strip()

            if number_match:
                item["phone"] = number_match.group(1).strip()

            if contact_match:
                item["contact_id"] = contact_match.group(1).strip()

            items.append(item)

        if items:

            return {
                "available": True,
                "count": len(items),
                "items": items,
                "error": None
            }

    return {
        "available": False,
        "count": None,
        "items": [],
        "error": (
            last_error
            or
            "Contacts provider did not expose records through ADB."
        )
    }


# ============================================================
# SMS
# ============================================================

def get_sms(
    serial: str
) -> dict[str, Any]:

    """
    Attempts SMS provider acquisition.

    No count is returned if Android prevents access.
    """

    commands = [
        (
            "content query "
            "--uri content://sms "
            "--projection _id:thread_id:address:date:type:body"
        )
    ]

    last_error = None

    for command in commands:

        result = run_shell(
            serial,
            command,
            timeout=60
        )

        if not result["ok"]:

            last_error = result["stderr"]
            continue

        output = result["stdout"].strip()

        if not output:
            continue

        items = []

        for line in output.splitlines():

            if not line.strip():
                continue

            item = {
                "raw": line
            }

            for field in [
                "_id",
                "thread_id",
                "address",
                "date",
                "type",
                "body"
            ]:

                match = re.search(
                    rf"{re.escape(field)}=(.*?)(?=,\s+[A-Za-z_][A-Za-z0-9_]*=|$)",
                    line
                )

                if match:

                    item[field] = (
                        match.group(1)
                        .strip()
                    )

            items.append(item)

        if items:

            return {
                "available": True,
                "count": len(items),
                "items": items,
                "error": None
            }

    return {
        "available": False,
        "count": None,
        "items": [],
        "error": (
            last_error
            or
            "SMS provider did not expose records through ADB."
        )
    }


# ============================================================
# SUSPICIOUS INDICATORS
# ============================================================

SUSPICIOUS_PACKAGE_TERMS = [
    "metasploit",
    "frida",
    "xposed",
    "magisk",
    "supersu",
    "busybox",
    "burp",
    "mitmproxy",
    "packetcapture"
]

SUSPICIOUS_PROCESS_TERMS = [
    "frida",
    "frida-server",
    "xposed",
    "metasploit"
]

HIGH_RISK_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.REQUEST_INSTALL_PACKAGES"
}


def analyze_packages(
    serial: str,
    packages: list[dict[str, Any]]
) -> dict[str, Any]:

    suspicious = []
    permission_findings = []

    for package in packages:

        name = package["package"]

        lower = name.lower()

        indicators = []

        for term in SUSPICIOUS_PACKAGE_TERMS:

            if term in lower:

                indicators.append(
                    {
                        "rule": "package-name-indicator",
                        "term": term,
                        "reason":
                            "Package name contains a known analysis/security-tool indicator."
                    }
                )

        permissions = get_package_permissions(
            serial,
            name
        )

        package["permissions"] = permissions

        high_risk = sorted(
            set(permissions)
            & HIGH_RISK_PERMISSIONS
        )

        if high_risk:

            permission_findings.append(
                {
                    "package": name,
                    "permissions": high_risk
                }
            )

        if indicators:

            suspicious.append(
                {
                    "package": name,
                    "indicators": indicators
                }
            )

    return {
        "suspicious_packages": suspicious,
        "permission_findings": permission_findings
    }


def analyze_processes(
    processes: list[dict[str, Any]]
) -> list[dict[str, Any]]:

    findings = []

    for process in processes:

        name = str(
            process.get(
                "name",
                ""
            )
        )

        lower = name.lower()

        for term in SUSPICIOUS_PROCESS_TERMS:

            if term in lower:

                findings.append(
                    {
                        "process": name,
                        "indicator": term,
                        "rule":
                            "running-process-indicator",
                        "reason":
                            "Running process name matches a known analysis/security-tool indicator."
                    }
                )

    return findings


# ============================================================
# FULL FORENSIC SCAN
# ============================================================

def perform_scan(
    serial: str
) -> dict[str, Any]:

    started = utc_now()

    device = get_device_info(
        serial
    )

    packages = get_packages(
        serial
    )

    package_analysis = analyze_packages(
        serial,
        packages
    )

    processes = get_processes(
        serial
    )

    process_findings = analyze_processes(
        processes
    )

    services = get_services(
        serial
    )

    components = get_components(
        serial
    )

    network = get_network(
        serial
    )

    contacts = get_contacts(
        serial
    )

    sms = get_sms(
        serial
    )

    suspicious_count = (
        len(
            package_analysis[
                "suspicious_packages"
            ]
        )
        +
        len(process_findings)
    )

    # Risk is deliberately simple and transparent.
    if suspicious_count == 0:
        risk = "NO_INDICATOR"
    elif suspicious_count <= 2:
        risk = "LOW"
    elif suspicious_count <= 5:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    finished = utc_now()

    result = {
        "schema_version": "2.0",

        "scan": {
            "started_at": started,
            "finished_at": finished,
            "serial": serial
        },

        "device": device,

        "applications": {
            "count": len(packages),
            "items": packages
        },

        "processes": {
            "count": len(processes),
            "items": processes
        },

        "services": services,

        "components": components,

        "network": network,

        "contacts": contacts,

        "sms": sms,

        "threat_analysis": {
            "risk_level": risk,
            "indicator_count": suspicious_count,

            "suspicious_packages":
                package_analysis[
                    "suspicious_packages"
                ],

            "suspicious_processes":
                process_findings,

            "permission_findings":
                package_analysis[
                    "permission_findings"
                ],

            "methodology": {
                "package_name":
                    "Keyword indicator only; not proof of malware.",

                "process_name":
                    "Keyword indicator only; not proof of malware.",

                "permissions":
                    "Permission combinations are indicators requiring analyst review.",

                "malware_detection":
                    "This agent does not claim malware infection without additional evidence."
            }
        }
    }

    return result


# ============================================================
# API
# ============================================================

@app.get("/")
def root():

    return {
        "service":
            "Smart Cyber Forensic ADB Agent",

        "status":
            "online",

        "adb":
            adb_executable()
            is not None,

        "version":
            "2.0.0"
    }


@app.get("/health")
def health():

    adb = adb_executable()

    return {
        "status": "ok",
        "agent_online": True,
        "adb_available": adb is not None,
        "adb_path": adb
    }


@app.get("/api/adb/status")
def adb_status():

    adb = adb_executable()

    devices = get_devices()

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

    device = None

    if authorized:

        device = get_device_info(
            authorized[0]["serial"]
        )

        device["state"] = "device"

    return {
        "agent_online": True,

        "adb_available":
            adb is not None,

        "adb_path":
            adb,

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

        "device":
            device,

        "error":
            None
            if adb
            else
            "ADB executable not found."
    }


@app.post("/api/adb/scan")
def start_scan():

    devices = get_devices()

    authorized = [
        d for d in devices
        if d["state"] == "device"
    ]

    if not authorized:

        raise HTTPException(
            status_code=400,
            detail=
                "No authorized Android device detected."
        )

    serial = authorized[0]["serial"]

    return perform_scan(
        serial
    )


@app.post("/api/adb/scan/{serial}")
def scan_specific_device(
    serial: str
):

    devices = get_devices()

    authorized_serials = {
        d["serial"]
        for d in devices
        if d["state"] == "device"
    }

    if serial not in authorized_serials:

        raise HTTPException(
            status_code=400,
            detail=
                "The requested device is not currently authorized."
        )

    return perform_scan(
        serial
    )


# ============================================================
# EXPORT
# ============================================================

def save_json_report(
    report: dict[str, Any]
) -> str:

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    serial = (
        report
        .get("device", {})
        .get("serial", "unknown")
    )

    filename = (
        f"forensic_report_"
        f"{serial}_"
        f"{timestamp}.json"
    )

    path = os.path.join(
        EXPORT_DIR,
        filename
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            indent=2,
            ensure_ascii=False
        )

    return path


def create_forensic_zip(
    report: dict[str, Any]
) -> str:

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    serial = (
        report
        .get("device", {})
        .get("serial", "unknown")
    )

    safe_serial = re.sub(
        r"[^A-Za-z0-9_.-]",
        "_",
        serial
    )

    directory = os.path.join(
        EXPORT_DIR,
        f"case_{safe_serial}_{timestamp}"
    )

    os.makedirs(
        directory,
        exist_ok=True
    )

    report_path = os.path.join(
        directory,
        "forensic_report.json"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            indent=2,
            ensure_ascii=False
        )

    evidence_manifest = {
        "created_at": utc_now(),
        "device_serial": serial,
        "files": []
    }

    for root, _, files in os.walk(directory):

        for filename in files:

            path = os.path.join(
                root,
                filename
            )

            relative = os.path.relpath(
                path,
                directory
            )

            evidence_manifest[
                "files"
            ].append(
                {
                    "file":
                        relative,

                    "sha256":
                        sha256_file(path)
                }
            )

    manifest_path = os.path.join(
        directory,
        "manifest.json"
    )

    with open(
        manifest_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            evidence_manifest,
            f,
            indent=2
        )

    zip_path = os.path.join(
        EXPORT_DIR,
        f"forensic_case_{safe_serial}_{timestamp}.zip"
    )

    with zipfile.ZipFile(
        zip_path,
        "w",
        zipfile.ZIP_DEFLATED
    ) as archive:

        for root, _, files in os.walk(
            directory
        ):

            for filename in files:

                path = os.path.join(
                    root,
                    filename
                )

                archive.write(
                    path,
                    os.path.relpath(
                        path,
                        directory
                    )
                )

    return zip_path


@app.post("/api/adb/export")
def export_scan():

    devices = get_devices()

    authorized = [
        d for d in devices
        if d["state"] == "device"
    ]

    if not authorized:

        raise HTTPException(
            status_code=400,
            detail=
                "No authorized Android device detected."
        )

    report = perform_scan(
        authorized[0]["serial"]
    )

    zip_path = create_forensic_zip(
        report
    )

    return {
        "success": True,
        "file": os.path.basename(
            zip_path
        ),
        "path": zip_path
    }


@app.get("/api/exports/{filename}")
def download_export(
    filename: str
):

    safe_name = os.path.basename(
        filename
    )

    path = os.path.join(
        EXPORT_DIR,
        safe_name
    )

    if not os.path.isfile(path):

        raise HTTPException(
            status_code=404,
            detail="Export not found."
        )

    return FileResponse(
        path,
        filename=safe_name
    )


# ============================================================
# SERVER
# ============================================================

if __name__ == "__main__":

    import uvicorn

    print()
    print("=" * 65)
    print(" SMART CYBER FORENSIC ADB AGENT")
    print("=" * 65)

    adb = adb_executable()

    print(
        "ADB:",
        adb or "NOT FOUND"
    )

    devices = get_devices()

    print(
        "Devices detected:",
        len(devices)
    )

    for device in devices:

        print(
            f"  {device['serial']} "
            f"[{device['state']}]"
        )

    print()
    print(
        f"Agent: http://{HOST}:{PORT}"
    )

    print("=" * 65)
    print()

    uvicorn.run(
        app,
        host=HOST,
        port=PORT
    )
