import pytest

from guardrail_mcp.scanning import SecretScanner

# Every credential below is assembled at runtime so the repository itself never
# contains a string that secret scanners (or push protection) would flag.
SAMPLES = {
    "github_token": "gh" + "p_" + "a" * 36,
    "anthropic_api_key": "sk-" + "ant-api03-" + "b" * 30,
    "aws_access_key_id": "AK" + "IA" + "C" * 16,
    "slack_token": "xo" + "xb-" + "1234567890-abcdef",
    "private_key": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "jwt": "ey" + "J" + "h" * 12 + ".ey" + "J" + "p" * 12 + "." + "s" * 12,
}


@pytest.mark.parametrize(("label", "secret"), SAMPLES.items())
def test_detects_common_credentials(label: str, secret: str) -> None:
    scanner = SecretScanner()
    assert label in scanner.find(f"please use {secret} for now")


@pytest.mark.parametrize("text", ["sk-learn is a library", "AKIA alone", "ghp_short", "Bearer of bad news"])
def test_ignores_ordinary_text(text: str) -> None:
    assert SecretScanner().find(text) == []


def test_redact_deep_counts_and_replaces() -> None:
    token = SAMPLES["github_token"]
    data = {"body": f"token {token}", "comments": [{"body": token}], "n": 3}
    clean, count = SecretScanner().redact_deep(data)
    assert count == 2
    assert token not in str(clean)
    assert clean["body"] == "token [REDACTED:github_token]"
    assert clean["n"] == 3


def test_extra_patterns() -> None:
    scanner = SecretScanner([r"\bACME-[0-9]{8}\b"])
    assert scanner.find("key ACME-12345678") == ["custom_1"]
