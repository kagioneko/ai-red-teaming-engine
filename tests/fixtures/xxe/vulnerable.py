from io import BytesIO
from lxml import etree
from flask import request, jsonify

def import_invoice():
    raw_xml = request.get_data()
    source = request.args.get("source", "upload")

    if not raw_xml:
        return jsonify({"error": "xml is required"}), 400

    parser = etree.XMLParser(
        resolve_entities=True,
        load_dtd=True,
        no_network=False,
    )
    tree = etree.parse(BytesIO(raw_xml), parser)

    root = tree.getroot()
    items = []
    for node in root.findall(".//item"):
        items.append({
            "sku": node.findtext("sku"),
            "qty": node.findtext("qty"),
        })

    return jsonify({
        "source": source,
        "invoice_id": root.findtext("id"),
        "items": items,
    })
