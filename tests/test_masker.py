"""masker モジュールのユニットテスト"""
import pytest
from redteam.masker import mask_secrets


def test_mask_openai_token():
    code = 'api_key = "sk-proj-abcdefghijklmnopqrst1234"'
    masked, count = mask_secrets(code)
    assert "sk-proj-" not in masked
    assert count > 0


def test_mask_github_pat():
    code = 'token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"'
    masked, count = mask_secrets(code)
    assert "ghp_" not in masked
    assert count > 0


def test_mask_password():
    code = 'password = "super_secret_pass"'
    masked, count = mask_secrets(code)
    assert "super_secret_pass" not in masked
    assert count > 0


def test_mask_connection_string():
    code = 'db_url = "postgresql://user:pass@localhost:5432/mydb"'
    masked, count = mask_secrets(code)
    assert "postgresql://" not in masked
    assert count > 0


def test_no_mask_normal_code():
    code = "def add(a, b):\n    return a + b"
    masked, count = mask_secrets(code)
    assert masked == code
    assert count == 0


def test_mask_count_multiple():
    code = """
api_key = "sk-abcdefghijklmnopqrst"
secret_key = "sk-zyxwvutsrqponmlkjihg"
"""
    _, count = mask_secrets(code)
    assert count >= 2


def test_mask_ip_when_enabled():
    code = "host = '192.168.1.100'"
    masked_off, _ = mask_secrets(code, mask_ips=False)
    masked_on, count = mask_secrets(code, mask_ips=True)
    assert "192.168.1.100" in masked_off
    assert "192.168.1.100" not in masked_on
