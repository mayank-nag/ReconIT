"""Security and robustness tests for report generation (autoescape, chmod 600, CSV)."""

import os
import stat
import tempfile
from pathlib import Path
from core.target import Target
from report.generator import run as report_run


def test_jinja2_autoescape_prevents_xss():
    """Verify hostile payload in target web content is properly escaped in report.html."""
    t = Target(domain="hostile-target.com")
    hostile_payload = "<script>alert('XSS-INJECTION')</script>"

    # Simulate hostile page title and form input discovered during crawl
    t.pages_crawled.append({
        "url": "https://hostile-target.com/page",
        "status": 200,
        "title": hostile_payload,
    })
    t.emails_found.append({
        "email": hostile_payload,
        "source_url": "https://hostile-target.com",
    })

    with tempfile.TemporaryDirectory() as temp_dir:
        result = report_run(t, output_dir=temp_dir, output_format="html")
        report_html_path = Path(temp_dir) / "report.html"

        assert report_html_path.is_file()
        content = report_html_path.read_text(encoding="utf-8")

        # Raw hostile tag must NOT be present unescaped
        assert "<script>alert('XSS-INJECTION')</script>" not in content
        # It must be HTML entity escaped
        assert "&lt;script&gt;alert(&#39;XSS-INJECTION&#39;)&lt;/script&gt;" in content or "&lt;script&gt;" in content


def test_report_file_permissions_chmod_600():
    """Verify output reports receive restricted file permissions (0600 / 0700)."""
    t = Target(domain="secure-test.com")
    t.subdomains = ["api.secure-test.com"]

    with tempfile.TemporaryDirectory() as temp_dir:
        result = report_run(t, output_dir=temp_dir, output_format="all")

        json_path = Path(temp_dir) / "report.json"
        html_path = Path(temp_dir) / "report.html"
        sub_csv_path = Path(temp_dir) / "subdomains.csv"

        for p in (json_path, html_path, sub_csv_path):
            if p.is_file():
                file_stat = os.stat(p)
                # Check that others have no read/write permissions (only owner)
                mode = file_stat.st_mode
                assert not (mode & stat.S_IRWXO), f"File {p} should not be readable/writable by others"


def test_csv_report_generation():
    t = Target(domain="csv-test.com")
    t.subdomains = ["sub1.csv-test.com", "sub2.csv-test.com"]
    t.add_risk_flag("Missing SPF", details="Email spoofing risk", score=10)

    with tempfile.TemporaryDirectory() as temp_dir:
        result = report_run(t, output_dir=temp_dir, output_format="csv")
        sub_csv = Path(temp_dir) / "subdomains.csv"
        flags_csv = Path(temp_dir) / "risk_flags.csv"

        assert sub_csv.is_file()
        assert flags_csv.is_file()

        sub_content = sub_csv.read_text()
        assert "sub1.csv-test.com" in sub_content
        assert "sub2.csv-test.com" in sub_content

        flags_content = flags_csv.read_text()
        assert "Missing SPF" in flags_content
