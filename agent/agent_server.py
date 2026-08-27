from flask import Flask, jsonify
from flask_cors import CORS

from agent import (
    adb_exists,
    device_status,
    collect_evidence,
    upload_evidence
)

app = Flask(__name__)

CORS(app)


@app.route("/")
def home():
    return jsonify({
        "service": "Smart Cyber Forensic ADB Agent",
        "status": "running"
    })


@app.route("/api/adb/status", methods=["GET"])
def adb_status():

    if not adb_exists():

        return jsonify({
            "adb_available": False,
            "connected_devices": 0,
            "authorized_devices": 0,
            "unauthorized_devices": 0,
            "offline_devices": 0,
            "devices": [],
            "error": (
                "ADB is not installed or "
                "ADB is not available in PATH."
            )
        })

    return jsonify(device_status())


@app.route("/api/adb/scan", methods=["POST"])
def adb_scan():

    status = device_status()

    if not status["adb_available"]:

        return jsonify({
            "error": "ADB is not installed."
        }), 400

    if status["authorized_devices"] == 0:

        return jsonify({
            "error":
                status["error"]
                or "No authorized Android device."
        }), 400

    serial = status["device"]["serial"]

    evidence = collect_evidence(serial)

    result = upload_evidence(evidence)

    return jsonify({
        "status": "completed",

        "result": result,

        "contacts": len(
            evidence["contacts"]
        ),

        "sms": len(
            evidence["sms"]
        ),

        "applications": len(
            evidence["packages"]
        ),

        "running": len(
            evidence["running_processes"]
        ),

        "suspicious": len(
            evidence["suspicious_package_flags"]
        )
    })


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=8765,
        debug=False
    )
