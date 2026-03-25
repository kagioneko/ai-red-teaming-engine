import subprocess
from flask import request, jsonify

def run_diagnostics():
    host = request.args.get("host", "")
    interface = request.args.get("interface", "eth0")
    mode = request.args.get("mode", "ping")
    count = request.args.get("count", "4")

    if not host:
        return jsonify({"error": "host is required"}), 400

    allowed_modes = {"ping": "ping", "trace": "traceroute"}
    tool = allowed_modes.get(mode, "ping")

    options = []
    if interface:
        options.append(f"-I {interface}")
    if count:
        options.append(f"-c {count}")

    cmd = f"{tool} {' '.join(options)} {host}"
    completed = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    body = {
        "command": cmd,
        "stdout": completed.stdout[-2000:],
        "stderr": completed.stderr[-1000:],
        "returncode": completed.returncode,
    }

    if completed.returncode != 0:
        return jsonify(body), 502
    return jsonify(body)
