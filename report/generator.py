"""
Report generator module.

Assembles final JSON + HTML + CSV reports from a Target object,
and generates an interactive graph visualization.
Enforces Jinja2 autoescape to protect against stored XSS from untrusted web targets,
and applies restricted file permissions (chmod 600) to protect intelligence outputs.
"""

import os
import csv
import json
from typing import Dict, Any
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.target import mask_secret


def _secure_write(file_path: str, content: str) -> None:
    """Write content to file and enforce chmod 600 permissions."""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
    try:
        os.chmod(file_path, 0o600)
    except Exception:
        pass


def _generate_csv_reports(target_data: Dict[str, Any], output_dir: str) -> list:
    """Generate structured CSV exports for subdomains and security risk flags."""
    created_files = []

    # 1. Subdomains CSV
    subdomains = target_data.get("subdomains", [])
    if subdomains:
        sub_csv_path = os.path.join(output_dir, "subdomains.csv")
        with open(sub_csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Target", "Subdomain"])
            for sub in subdomains:
                writer.writerow([target_data.get("target", ""), sub])
        try:
            os.chmod(sub_csv_path, 0o600)
        except Exception:
            pass
        created_files.append(f"subdomains.csv → {sub_csv_path}")

    # 2. Risk Flags CSV
    risk_flags = target_data.get("risk_flags", [])
    if risk_flags:
        flags_csv_path = os.path.join(output_dir, "risk_flags.csv")
        with open(flags_csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Target", "Risk Flag", "Severity Score", "Details"])
            for rf in risk_flags:
                writer.writerow([
                    target_data.get("target", ""),
                    rf.get("flag", ""),
                    rf.get("score", ""),
                    rf.get("details", ""),
                ])
        try:
            os.chmod(flags_csv_path, 0o600)
        except Exception:
            pass
        created_files.append(f"risk_flags.csv → {flags_csv_path}")

    return created_files


def run(target, output_dir: str = "./output", output_format: str = "all") -> Dict[str, Any]:
    """Generate reports from scan results.

    Args:
        target: A Target instance with all accumulated scan data.
        output_dir: Directory to write reports to.
        output_format: 'json', 'html', 'csv', or 'all'.

    Returns:
        Dict with 'data' containing list of files created, 'risk_flags', and 'errors'.
    """
    result: Dict[str, Any] = {"data": {"files_created": []}, "risk_flags": [], "errors": []}

    os.makedirs(output_dir, exist_ok=True)
    try:
        os.chmod(output_dir, 0o700)
    except Exception:
        pass

    try:
        target_data = target.to_dict()
    except Exception as e:
        result["errors"].append(f"Failed to extract data from target: {e}")
        return result

    # --- JSON Report ---
    if output_format in ["json", "all"]:
        try:
            json_path = os.path.join(output_dir, "report.json")
            _secure_write(json_path, target.to_json())
            result["data"]["files_created"].append(f"report.json → {json_path}")
        except Exception as e:
            result["errors"].append(f"Failed to write JSON report: {e}")

    # --- CSV Reports ---
    if output_format in ["csv", "all"]:
        try:
            csv_files = _generate_csv_reports(target_data, output_dir)
            result["data"]["files_created"].extend(csv_files)
        except Exception as e:
            result["errors"].append(f"Failed to write CSV report: {e}")

    # --- HTML Report (with secure Jinja2 autoescaping) ---
    if output_format in ["html", "all"]:
        try:
            template_dir = os.path.join(os.path.dirname(__file__), "templates")
            env = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(["html", "xml"]),
            )
            template = env.get_template("report.html")
            html_content = template.render(**target_data)

            html_path = os.path.join(output_dir, "report.html")
            _secure_write(html_path, html_content)
            result["data"]["files_created"].append(f"report.html → {html_path}")
        except Exception as e:
            result["errors"].append(f"Failed to write HTML report: {e}")

    # --- Graph ---
    if output_format in ["graph", "all"]:
        try:
            from . import graph

            graph_path = os.path.join(output_dir, "graph.html")
            if graph.generate(target_data, graph_path):
                try:
                    os.chmod(graph_path, 0o600)
                except Exception:
                    pass
                result["data"]["files_created"].append(f"graph.html → {graph_path}")
            else:
                result["errors"].append("Graph generation returned False.")
        except ImportError:
            result["errors"].append("Graph module not available (missing networkx/pyvis?).")
        except Exception as e:
            result["errors"].append(f"Failed to generate graph: {e}")

    return result
