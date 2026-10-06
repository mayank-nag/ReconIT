"""Unit tests for CVE lookup module and confidence levels."""

from modules.cve_lookup import run as cve_run


def test_cve_lookup_matches_and_confidence():
    tech_data = {
        "server": "Apache",
        "cms": "WordPress",
        "frameworks": ["Express"],
        "detected_technologies": ["Apache", "WordPress", "Express"],
    }
    result = cve_run(tech_data, timeout=1)
    cves = result["data"]["cve_matches"]
    assert len(cves) > 0

    # Ensure each match has confidence rating
    for cve in cves:
        assert "confidence" in cve
        assert "INDICATIVE" in cve["confidence"]
        assert "note" in cve

    # Ensure disclaimer is included
    assert "disclaimer" in result["data"]
    assert "backport" in result["data"]["disclaimer"].lower()


def test_cve_lookup_empty_tech():
    result = cve_run({})
    assert result["data"]["cve_matches"] == []
    assert result["risk_flags"] == []
