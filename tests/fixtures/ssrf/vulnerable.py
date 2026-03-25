import requests
from flask import request, jsonify

def fetch_preview():
    target_url = request.args.get("url", "")
    timeout = float(request.args.get("timeout", "3"))
    include_headers = request.args.get("headers", "false") == "true"

    if not target_url:
        return jsonify({"error": "url is required"}), 400

    upstream = requests.get(
        target_url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "PreviewBot/1.0"},
    )

    body = {
        "status": upstream.status_code,
        "content_type": upstream.headers.get("Content-Type"),
        "preview": upstream.text[:500],
        "url": target_url,
    }

    if include_headers:
        body["headers"] = dict(upstream.headers)

    return jsonify(body)
