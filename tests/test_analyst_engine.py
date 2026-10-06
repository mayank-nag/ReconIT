"""Unit tests for Analyst Engine (rule-based heuristic + LLM fallback)."""

from modules.ai_analyst import generate_local_analysis, run as analyst_run


def test_analyst_engine_rule_based_mode():
    target_data = {
        "target": "example.com",
        "risk_score": 75,
        "risk_level": "HIGH",
        "risk_flags": [
            {"flag": "Missing SPF", "score": 10},
            {"flag": "Missing DMARC", "score": 10},
            {"flag": "SSL expired", "score": 25},
        ],
        "subdomains": ["api.example.com", "dev.example.com"],
        "technologies": {
            "server": "Nginx",
            "frameworks": ["React"],
            "security_headers": {"CSP": "missing", "HSTS": "missing"},
        },
        "dns_data": {"A": ["93.184.216.34"]},
        "ssl_data": {"not_after": "2023-01-01T00:00:00Z"},
        "whois_data": {"registrar": "Example Registrar"},
        "pages_crawled": [{"url": "https://example.com/.env", "status": 200}],
    }

    analysis = generate_local_analysis(target_data)
    assert analysis["mode"] == "Rule-Based Heuristic Engine (Offline)"
    assert len(analysis["executive_summary"]) >= 3
    assert len(analysis["narrative_sections"]) == 3
    assert len(analysis["remediation_roadmap"]) >= 2

    # Verify run wrapper uses local engine by default when no API keys are provided
    wrapped = analyst_run(target_data, api_keys={})
    assert wrapped["data"]["mode"] == "Rule-Based Heuristic Engine (Offline)"
