"""サンプル: 意図的な脆弱性を含むPythonコード（テスト用）"""
import sqlite3
import hashlib
import os

# ハードコードされたシークレット（意図的な脆弱性）
API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz"
DB_PASSWORD = "admin123"

def get_user(username: str, conn: sqlite3.Connection):
    """SQLインジェクション脆弱性あり"""
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = conn.execute(query)
    return cursor.fetchone()


def hash_password(password: str) -> str:
    """脆弱なハッシュ関数（MD5）"""
    return hashlib.md5(password.encode()).hexdigest()


def read_file(filename: str) -> str:
    """パストラバーサル脆弱性あり"""
    base_dir = "/var/data/"
    path = base_dir + filename  # ../../../etc/passwd などが可能
    with open(path) as f:
        return f.read()


def process_user_data(data: dict) -> dict:
    """入力検証なし"""
    # dataの内容を検証せずに処理
    result = {
        "id": data["id"],
        "email": data["email"],
        "role": data.get("role", "user"),
    }
    return result


def execute_command(cmd: str) -> str:
    """OSコマンドインジェクション"""
    import subprocess
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
