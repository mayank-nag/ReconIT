"""Unit tests for ScopeGuard and WildcardDnsDetector."""

import tempfile
from pathlib import Path
from core.scope import ScopeGuard, WildcardDnsDetector


def test_scope_guard_root_and_subdomains():
    guard = ScopeGuard(root_domain="example.com")
    assert guard.is_in_scope("example.com") is True
    assert guard.is_in_scope("api.example.com") is True
    assert guard.is_in_scope("dev.sub.example.com") is True
    assert guard.is_in_scope("https://admin.example.com:443/login") is True

    # Third-party out-of-scope domains must be rejected
    assert guard.is_in_scope("notexample.com") is False
    assert guard.is_in_scope("s3.amazonaws.com") is False
    assert guard.is_in_scope("azureedge.net") is False
    assert guard.is_in_scope("google.com") is False


def test_scope_guard_custom_list():
    guard = ScopeGuard(
        root_domain="example.com",
        allowed_scope=["example.com", "partner-api.net", "staging.corp"],
    )
    assert guard.is_in_scope("example.com") is True
    assert guard.is_in_scope("partner-api.net") is True
    assert guard.is_in_scope("auth.partner-api.net") is True
    assert guard.is_in_scope("staging.corp") is True
    assert guard.is_in_scope("random.com") is False


def test_scope_guard_file_loading():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("# Scope file\nexample.com\nallowed-partner.org\n# another comment\n")
        temp_path = f.name

    try:
        guard = ScopeGuard("example.com", allowed_scope=temp_path)
        assert guard.is_in_scope("allowed-partner.org") is True
        assert guard.is_in_scope("sub.allowed-partner.org") is True
        assert guard.is_in_scope("attacker.com") is False
    finally:
        Path(temp_path).unlink()


def test_scope_guard_filter():
    guard = ScopeGuard("example.com")
    candidates = [
        "api.example.com",
        "s3.us-east-1.amazonaws.com",
        "dev.example.com",
        "cloudflare.net",
    ]
    filtered = guard.filter_in_scope(candidates)
    assert filtered == ["api.example.com", "dev.example.com"]


def test_wildcard_dns_detector_false_positive():
    detector = WildcardDnsDetector("example.com")
    detector.is_wildcard = True
    detector.wildcard_ips = {"93.184.216.34"}

    assert detector.is_false_positive(["93.184.216.34"]) is True
    assert detector.is_false_positive(["192.168.1.1"]) is False
