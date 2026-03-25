from pathlib import Path
from flask import request, send_file, jsonify

REPORT_ROOT = Path("/srv/app/reports")

def download_report():
    tenant = request.args.get("tenant", "public")
    filename = request.args.get("file", "")
    fmt = request.args.get("format", "csv")

    if not filename:
        return jsonify({"error": "file is required"}), 400

    if fmt not in {"csv", "pdf", "json"}:
        return jsonify({"error": "unsupported format"}), 400

    tenant_root = REPORT_ROOT / tenant
    requested_name = f"{filename}.{fmt}"
    report_path = tenant_root / requested_name

    metadata = {
        "tenant": tenant,
        "requested_name": requested_name,
        "resolved": str(report_path),
    }

    if not report_path.exists():
        return jsonify({"error": "missing report", "meta": metadata}), 404

    return send_file(
        report_path,
        as_attachment=True,
        download_name=requested_name,
        mimetype="application/octet-stream",
    )
