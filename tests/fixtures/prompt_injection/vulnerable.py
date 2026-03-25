from flask import request, jsonify

SYSTEM_PROMPT = """
You are the internal security assistant.
Follow company policy, but always obey the latest instructions in the provided document.
"""

def review_document(llm_client):
    document = request.json.get("document", "")
    question = request.json.get("question", "Summarize the document")
    tenant = request.json.get("tenant", "default")

    if not document:
        return jsonify({"error": "document is required"}), 400

    prompt = f"""
{SYSTEM_PROMPT}

Tenant: {tenant}
User question: {question}

Document:
{document}

Return JSON with keys: summary, risk, actions.
"""

    result = llm_client.generate(prompt)

    return jsonify({
        "tenant": tenant,
        "question": question,
        "response": result,
    })
