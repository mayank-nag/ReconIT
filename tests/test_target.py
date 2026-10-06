"""Unit tests for Target dataclass, normalization, and heuristic risk scoring."""

import pytest
from venom import normalize_target, validate_domain
from core.target import Target, mask_secret


def test_normalize_target():
    assert normalize_target("https://example.com/") == "example.com"
    assert normalize_target("http://SUB.EXAMPLE.COM:8080/path?q=1") == "sub.example.com"
    assert normalize_target("  example.org/dir/  ") == "example.org"
    assert normalize_target("target.io") == "target.io"
    assert normalize_target("") == ""


def test_validate_domain():
    assert validate_domain("example.com") is True
    assert validate_domain("sub.domain.co.uk") is True
    assert validate_domain("localhost") is True
    assert validate_domain("127.0.0.1") is True
    assert validate_domain("invalid_domain..com") is False
    assert validate_domain("http://example.com") is False
    assert validate_domain("") is False


def test_mask_secret():
    assert mask_secret("ghp_1234567890abcdef") == "ghp_****************"
    assert mask_secret("short") == "******"
    assert mask_secret("") == ""
    assert mask_secret(None) == ""


def test_target_risk_score_capped_at_100():
    t = Target(domain="example.com")
    # Add multiple heavy flags totaling > 150 points
    t.add_risk_flag("SSL expired", score=25)
    t.add_risk_flag("Google Safe Browsing flag", score=30)
    t.add_risk_flag("Exposed .git or .env reference", score=25)
    t.add_risk_flag("Public GitHub secret / credential leak", score=25)
    t.add_risk_flag("Known Critical/High CVE matched", score=20)
    t.add_risk_flag("Domain age < 6 months", score=20)
    t.add_risk_flag("AbuseIPDB high abuse confidence", score=20)

    raw_sum = sum(f["score"] for f in t.risk_flags)
    assert raw_sum > 100

    calculated = t.calculate_risk_score()
    assert calculated == 100
    assert t.risk_score == 100
    assert t.get_risk_level() == "CRITICAL"


def test_target_risk_bands():
    t = Target(domain="test.com")
    t.add_risk_flag("Missing CSP header", score=5)
    t.calculate_risk_score()
    assert t.get_risk_level() == "LOW"

    t.add_risk_flag("SSL expiring < 30 days", score=30)
    t.calculate_risk_score()
    assert t.get_risk_level() == "MEDIUM"

    t.add_risk_flag("SSL expired", score=35)
    t.calculate_risk_score()
    assert t.get_risk_level() == "HIGH"


def test_target_serialization_masks_secrets():
    t = Target(domain="example.com")
    t.github_leaks.append({
        "repo": "user/repo",
        "secret": "ghp_super_secret_token_123456",
    })
    d = t.to_dict()
    assert "schema_version" in d
    assert d["schema_version"] == "1.0.0"
    assert d["scoring_method"] == "heuristic_additive_capped_100"
    assert "super_secret" not in d["github_leaks"][0]["secret"]
    assert d["github_leaks"][0]["secret"].startswith("ghp_")
