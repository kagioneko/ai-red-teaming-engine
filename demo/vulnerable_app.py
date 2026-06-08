"""Example Flask app with intentional security vulnerabilities (for demo purposes)."""
import sqlite3
import subprocess
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET_KEY = "hardcoded_secret_abc123"
DB_PATH = "users.db"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect(DB_PATH)
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = conn.execute(query).fetchone()
    if result:
        return jsonify({"token": SECRET_KEY, "user": username})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/run", methods=["POST"])
def run_command():
    # Command injection vulnerability
    cmd = request.json.get("cmd", "")
    output = subprocess.check_output(cmd, shell=True)
    return jsonify({"output": output.decode()})


@app.route("/file", methods=["GET"])
def read_file():
    # Path traversal vulnerability
    filename = request.args.get("name")
    path = os.path.join("/var/app/data", filename)
    with open(path) as f:
        return f.read()
