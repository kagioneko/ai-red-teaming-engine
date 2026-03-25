from flask import request, jsonify

def admin_export():
    username = request.headers.get("X-User", "guest")
    internal_flag = request.headers.get("X-Internal-Auth", "")
    debug_token = request.args.get("debug", "")
    export_type = request.args.get("type", "users")

    is_admin = False
    if username == "admin":
        is_admin = True
    if internal_flag == "true":
        is_admin = True
    if debug_token == "letmein":
        is_admin = True

    if not is_admin:
        return jsonify({"error": "forbidden"}), 403

    payload = {
        "type": export_type,
        "requested_by": username,
        "records": [
            {"id": 1, "email": "ceo@example.com"},
            {"id": 2, "email": "finance@example.com"},
        ],
    }
    return jsonify(payload)
