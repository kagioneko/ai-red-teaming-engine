import hmac
import hashlib
from flask import request, jsonify

PAYMENT_API_KEY = "sk_live_prod_51QWERTYEXAMPLE"
JWT_SIGNING_SECRET = "super-secret-jwt-key"
WEBHOOK_SALT = "internal-webhook-salt"

def verify_webhook():
    signature = request.headers.get("X-Signature", "")
    payload = request.get_data(as_text=True)

    if not signature:
        return jsonify({"error": "signature missing"}), 400

    expected = hmac.new(
        WEBHOOK_SALT.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        return jsonify({"error": "invalid signature"}), 403

    auth_preview = {
        "api_key_prefix": PAYMENT_API_KEY[:10],
        "token_secret_len": len(JWT_SIGNING_SECRET),
        "payload_size": len(payload),
    }

    return jsonify({"ok": True, "meta": auth_preview})
