"""
dashboard.py のカスタムルール API テスト
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

# Flask テストクライアントを使用
pytest.importorskip("flask")
pytest.importorskip("yaml")


@pytest.fixture
def client(tmp_path):
    """一時ディレクトリを使ったテスト用 Flask クライアント"""
    from redteam import dashboard as dash

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    rules_file = tmp_path / ".redteam-rules.yaml"

    dash._logs_dir = logs_dir
    dash._rules_file = rules_file

    dash.app.config["TESTING"] = True
    with dash.app.test_client() as c:
        yield c


# ─── GET /api/rules ───────────────────────────────────────────────────────────

def test_get_rules_empty(client):
    """ルールファイルが存在しない場合は空リストを返す"""
    res = client.get("/api/rules")
    assert res.status_code == 200
    data = res.get_json()
    assert data["rules"] == []


def test_get_rules_with_file(client, tmp_path):
    """既存ルールファイルを正しく読み込む"""
    from redteam import dashboard as dash
    import yaml

    rules_data = {
        "rules": [
            {"id": "CUS-001", "name": "eval使用", "pattern": "eval\\s*\\(", "severity": "High",
             "category": "Code Injection", "message": "危険", "enabled": True}
        ]
    }
    dash._rules_file.write_text(yaml.dump(rules_data, allow_unicode=True))

    res = client.get("/api/rules")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["rules"]) == 1
    assert data["rules"][0]["id"] == "CUS-001"


# ─── POST /api/rules ─────────────────────────────────────────────────────────

def test_save_new_rule(client):
    """新規ルールを保存できる"""
    rule = {
        "id": "CUS-001", "name": "eval使用", "pattern": "eval\\s*\\(",
        "severity": "High", "category": "Code Injection",
        "message": "危険", "file_glob": "*.py", "enabled": True,
    }
    res = client.post("/api/rules", json={"rule": rule, "editing_id": None})
    assert res.status_code == 200
    assert res.get_json()["ok"] is True

    # 永続化確認
    res2 = client.get("/api/rules")
    assert len(res2.get_json()["rules"]) == 1


def test_save_rule_missing_name(client):
    """name が未指定なら 400 エラー"""
    rule = {"id": "CUS-001", "pattern": "eval\\s*\\(", "severity": "High"}
    res = client.post("/api/rules", json={"rule": rule})
    assert res.status_code == 400


def test_save_rule_missing_pattern(client):
    """pattern が未指定なら 400 エラー"""
    rule = {"id": "CUS-001", "name": "eval", "severity": "High"}
    res = client.post("/api/rules", json={"rule": rule})
    assert res.status_code == 400


def test_save_rule_invalid_regex(client):
    """無効な正規表現なら 400 エラー"""
    rule = {"id": "CUS-001", "name": "bad", "pattern": "[invalid(", "severity": "High", "message": "x"}
    res = client.post("/api/rules", json={"rule": rule})
    assert res.status_code == 400
    assert "正規表現" in res.get_json()["error"]


def test_save_rule_duplicate_id(client):
    """ID 重複で 409 エラー"""
    rule = {"id": "CUS-001", "name": "eval", "pattern": "eval\\(", "severity": "High", "message": "x"}
    client.post("/api/rules", json={"rule": rule})
    res = client.post("/api/rules", json={"rule": rule})
    assert res.status_code == 409


def test_update_existing_rule(client):
    """editing_id 指定で既存ルールを更新できる"""
    rule = {"id": "CUS-001", "name": "eval使用", "pattern": "eval\\(", "severity": "High", "message": "旧"}
    client.post("/api/rules", json={"rule": rule})

    rule_updated = {**rule, "message": "新しいメッセージ", "severity": "Critical"}
    res = client.post("/api/rules", json={"rule": rule_updated, "editing_id": "CUS-001"})
    assert res.status_code == 200

    rules = client.get("/api/rules").get_json()["rules"]
    assert len(rules) == 1
    assert rules[0]["message"] == "新しいメッセージ"
    assert rules[0]["severity"] == "Critical"


def test_save_rule_invalid_severity_defaults_medium(client):
    """不正な severity は Medium にフォールバック"""
    rule = {"id": "CUS-001", "name": "x", "pattern": "x", "severity": "UNKNOWN", "message": "x"}
    client.post("/api/rules", json={"rule": rule})
    rules = client.get("/api/rules").get_json()["rules"]
    assert rules[0]["severity"] == "Medium"


# ─── DELETE /api/rules/<id> ───────────────────────────────────────────────────

def test_delete_rule(client):
    """ルールを削除できる"""
    rule = {"id": "CUS-001", "name": "eval", "pattern": "eval\\(", "severity": "High", "message": "x"}
    client.post("/api/rules", json={"rule": rule})

    res = client.delete("/api/rules/CUS-001")
    assert res.status_code == 200
    assert res.get_json()["ok"] is True

    rules = client.get("/api/rules").get_json()["rules"]
    assert rules == []


def test_delete_nonexistent_rule(client):
    """存在しない ID を削除しようとすると 404"""
    res = client.delete("/api/rules/NOTEXIST")
    assert res.status_code == 404


# ─── POST /api/rules/test ─────────────────────────────────────────────────────

def test_pattern_test_hit(client):
    """マッチするコードに対してヒット行を返す"""
    res = client.post("/api/rules/test", json={
        "pattern": "eval\\s*\\(",
        "code": "x = 1\nresult = eval(user_input)\ny = 2",
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] == 1
    assert data["hits"][0]["lineno"] == 2
    assert "eval" in data["hits"][0]["match"]


def test_pattern_test_no_hit(client):
    """マッチしない場合は空リスト"""
    res = client.post("/api/rules/test", json={
        "pattern": "eval\\s*\\(",
        "code": "x = 1\ny = 2",
    })
    assert res.status_code == 200
    assert res.get_json()["count"] == 0
    assert res.get_json()["hits"] == []


def test_pattern_test_multiple_hits(client):
    """複数ヒットを全て返す"""
    res = client.post("/api/rules/test", json={
        "pattern": "password",
        "code": "password = 'abc'\nuser_password = 'xyz'\nok = True",
    })
    data = res.get_json()
    assert data["count"] == 2


def test_pattern_test_missing_pattern(client):
    """pattern 未指定なら 400"""
    res = client.post("/api/rules/test", json={"code": "x = 1"})
    assert res.status_code == 400


def test_pattern_test_invalid_regex(client):
    """無効な正規表現なら 400"""
    res = client.post("/api/rules/test", json={"pattern": "[bad(", "code": "x"})
    assert res.status_code == 400


# ─── ページルート ─────────────────────────────────────────────────────────────

def test_rules_page_renders(client):
    """GET /rules が 200 を返す"""
    res = client.get("/rules")
    assert res.status_code == 200
    assert b"RedTeam Dashboard" in res.data


def test_index_page_renders(client):
    """GET / が 200 を返す"""
    res = client.get("/")
    assert res.status_code == 200
    assert b"RedTeam Dashboard" in res.data
