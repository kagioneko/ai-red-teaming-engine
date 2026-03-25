import base64
import pickle
from flask import request, jsonify

def restore_session():
    raw_state = request.cookies.get("shopping_state", "")
    source = request.args.get("source", "cookie")
    refresh = request.args.get("refresh", "false") == "true"

    if not raw_state:
        return jsonify({"items": [], "source": source, "refresh": refresh})

    try:
        decoded = base64.b64decode(raw_state)
    except Exception:
        return jsonify({"error": "invalid state"}), 400

    state = pickle.loads(decoded)

    items = []
    for item in state.get("items", []):
        items.append({
            "sku": item.get("sku"),
            "qty": item.get("qty", 1),
        })

    response = {
        "items": items,
        "coupon": state.get("coupon"),
        "source": source,
        "refresh": refresh,
    }
    return jsonify(response)
