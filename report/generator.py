"""
Report generator module.

Assembles the final JSON + HTML report from a Target object,
and generates an interactive graph visualization.
"""

import os
import json
from typing import Dict, Any
from pathlib import Path
from jinja2 import Environment, FileSystemLoader


def run(target, output_dir: str = './output', output_format: str = 'all') -> Dict[str, Any]:
    """Generate reports from scan results.

    Args:
        target: A Target instance with all accumulated scan data.
        output_dir: Directory to write reports to.
        output_format: 'json', 'html', or 'all'.

    Returns:
        Dict with 'data' containing list of files created, 'risk_flags', and 'errors'.
    """
    result: Dict[str, Any] = {'data': {'files_created': []}, 'risk_flags': [], 'errors': []}

    os.makedirs(output_dir, exist_ok=True)

    try:
        target_data = target.to_dict()
    except Exception as e:
        result['errors'].append(f'Failed to extract data from target: {e}')
        return result

    # --- JSON Report ---
    if output_format in ['json', 'all']:
        try:
            json_path = os.path.join(output_dir, 'report.json')
            with open(json_path, 'w', encoding='utf-8') as f:
                f.write(target.to_json())
            result['data']['files_created'].append(f'report.json → {json_path}')
        except Exception as e:
            result['errors'].append(f'Failed to write JSON report: {e}')

    # --- HTML Report ---
    if output_format in ['html', 'all']:
        try:
            template_dir = os.path.join(os.path.dirname(__file__), 'templates')
            env = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=False,  # Template is self-contained HTML, not user-facing web app
            )
            template = env.get_template('report.html')
            html_content = template.render(**target_data)

            html_path = os.path.join(output_dir, 'report.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            result['data']['files_created'].append(f'report.html → {html_path}')
        except Exception as e:
            result['errors'].append(f'Failed to write HTML report: {e}')

    # --- Graph ---
    if output_format == 'all':
        try:
            from . import graph
            graph_path = os.path.join(output_dir, 'graph.html')
            if graph.generate(target_data, graph_path):
                result['data']['files_created'].append(f'graph.html → {graph_path}')
            else:
                result['errors'].append('Graph generation returned False.')
        except ImportError:
            result['errors'].append('Graph module not available (missing networkx/pyvis?).')
        except Exception as e:
            result['errors'].append(f'Failed to generate graph: {e}')

    return result
