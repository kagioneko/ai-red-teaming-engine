import hashlib
import random
import time
from flask import request, jsonify

def issue_reset_token():
    email = request.json.get("email", "").strip().lower()
    tenant = request.json.get("tenant", "default")
    purpose = request.json.get("purpose", "password_reset")

    if not email:
        return jsonify({"error": "email is required"}), 400

    seed = f"{email}:{tenant}:{purpose}:{int(time.time())}:{random.randint(1000, 9999)}"
    token = hashlib.md5(seed.encode()).hexdigest()

    audit = {
        "email": email,
        "tenant": tenant,
        "purpose": purpose,
        "length": len(token),
    }

    return jsonify({
        "token": token,
        "expires_in": 900,
        "audit": audit,
    })
