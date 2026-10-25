"""
Security Safeguard Tests
Tests PII redaction, path traversal protection, and CSV formula injection neutralization.
"""

from app.ai.sanitization import sanitize_line, sanitize_csv_field
from app.ingestion.validation import sanitize_filename, validate_file_metadata


def test_bearer_token_redaction():
    raw = "User requested with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    cleaned, stats = sanitize_line(raw)
    assert "[REDACTED_TOKEN]" in cleaned
    assert "eyJhbGciOi" not in cleaned
    assert stats["tokens"] == 1


def test_password_redaction():
    raw = 'Login attempt password="SuperSecret123!" for user admin'
    cleaned, stats = sanitize_line(raw)
    assert "[REDACTED_PASSWORD]" in cleaned
    assert "SuperSecret123!" not in cleaned
    assert stats["passwords"] == 1


def test_path_traversal_prevention():
    unsafe_name = "../../../../etc/passwd"
    safe = sanitize_filename(unsafe_name)
    assert "/" not in safe
    assert ".." not in safe
    assert safe == "passwd"


def test_dangerous_extension_rejection():
    is_valid, msg = validate_file_metadata("malicious_script.sh", 1024, 10000)
    assert not is_valid
    assert "forbidden" in msg


def test_csv_formula_injection_defense():
    unsafe_formula = "=SUM(1+1)"
    safe = sanitize_csv_field(unsafe_formula)
    assert safe.startswith('"\'=')
