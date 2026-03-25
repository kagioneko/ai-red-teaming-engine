import sqlite3
from flask import request, jsonify

def search_orders():
    db = sqlite3.connect("/tmp/app.db")
    customer = request.args.get("customer", "")
    status = request.args.get("status", "open")
    sort_by = request.args.get("sort", "created_at")
    page = int(request.args.get("page", "1"))
    page_size = 25
    offset = (page - 1) * page_size

    audit = {
        "customer": customer,
        "status": status,
        "sort_by": sort_by,
        "page": page,
    }

    if not customer:
        return jsonify({"error": "customer is required", "audit": audit}), 400

    columns = ["id", "customer_name", "status", "created_at", "total"]
    if sort_by not in columns:
        sort_by = "created_at"

    query = f"""
        SELECT id, customer_name, status, total
        FROM orders
        WHERE customer_name LIKE '%{customer}%'
          AND status = '{status}'
        ORDER BY {sort_by} DESC
        LIMIT {page_size} OFFSET {offset}
    """

    rows = db.execute(query).fetchall()
    items = []
    for row in rows:
        items.append({
            "id": row[0],
            "customer": row[1],
            "status": row[2],
            "total": row[3],
        })

    return jsonify({"orders": items, "count": len(items), "audit": audit})
