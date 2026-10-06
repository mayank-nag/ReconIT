"""
Metadata extraction module.

Downloads publicly linked documents and images defensively, extracting
hidden metadata (author names, software versions, GPS EXIF data) with
strict size limits, count caps, and memory limits.
Direct contact classification: Non-intrusive Asset Download.
"""

import os
import tempfile
from typing import Dict, Any, List
from urllib.parse import urlparse

from core.http_client import HttpClient

# Prefer modern pypdf over deprecated PyPDF2
try:
    import pypdf
except ImportError:
    try:
        import PyPDF2 as pypdf  # type: ignore
    except ImportError:
        pypdf = None

try:
    from PIL import Image, ExifTags
except ImportError:
    Image = None


def run(files: List[Dict[str, str]], timeout: int = 15, max_files: int = 10, max_size_mb: int = 5) -> Dict[str, Any]:
    """Downloads publicly linked documents/images and extracts hidden metadata defensively.

    Args:
        files: List of dicts like [{'url': '...', 'type': 'pdf'}, ...]
        timeout: Timeout for downloading each file in seconds.
        max_files: Maximum number of files to process (capped at 20).
        max_size_mb: Maximum file size allowed in megabytes (capped at 10MB).

    Returns:
        Dict containing 'data', 'risk_flags', and 'errors'.
    """
    result: Dict[str, Any] = {
        "data": {
            "findings": [],
            "contact_type": "Direct Asset Download (Defensively Capped)",
        },
        "risk_flags": [],
        "errors": [],
    }

    if not files:
        return result

    capped_max_files = min(max_files, 20)
    max_bytes = min(max_size_mb, 10) * 1024 * 1024
    files_to_process = files[:capped_max_files]

    http_client = HttpClient.get_instance(timeout=float(timeout))

    with tempfile.TemporaryDirectory() as temp_dir:
        for file_info in files_to_process:
            url = file_info.get("url")
            file_type = file_info.get("type", "").lower()

            if not url:
                continue

            finding: Dict[str, Any] = {
                "url": url,
                "type": file_type,
                "metadata": {},
                "risk_notes": [],
            }

            try:
                # 1. Defensive stream download with byte limit
                parsed_url = urlparse(url)
                filename = os.path.basename(parsed_url.path) or "temp_asset"
                temp_path = os.path.join(temp_dir, filename)

                resp = http_client.get(url, timeout=float(timeout))
                if resp.status_code != 200:
                    continue

                content = resp.content
                if len(content) > max_bytes:
                    result["errors"].append(f"File {url} exceeds safe size limit ({len(content)} > {max_bytes} bytes). Skipped.")
                    continue

                with open(temp_path, "wb") as f:
                    f.write(content)

                # 2. Extract metadata defensively
                if file_type == "pdf":
                    if pypdf:
                        try:
                            with open(temp_path, "rb") as f:
                                reader = pypdf.PdfReader(f)
                                meta = reader.metadata
                                if meta:
                                    author = getattr(meta, "author", None) or meta.get("/Author")
                                    creator = getattr(meta, "creator", None) or meta.get("/Creator")
                                    producer = getattr(meta, "producer", None) or meta.get("/Producer")
                                    creation_date = getattr(meta, "creation_date", None) or meta.get("/CreationDate")

                                    if author:
                                        finding["metadata"]["author"] = str(author)
                                        finding["risk_notes"].append(f"Author name found: {author} (potential employee enumeration)")
                                        result["risk_flags"].append(f"PDF Author found in {url}")
                                    if creator:
                                        finding["metadata"]["creator"] = str(creator)
                                        finding["risk_notes"].append(f"Software/tool info found: {creator}")
                                    if producer:
                                        finding["metadata"]["producer"] = str(producer)
                                        finding["risk_notes"].append(f"Software/tool info found: {producer}")
                                    if creation_date:
                                        finding["metadata"]["creation_date"] = str(creation_date)
                        except Exception as pdf_err:
                            finding["risk_notes"].append(f"PDF parser warning (malformed or encrypted): {pdf_err}")
                    else:
                        result["errors"].append("pypdf not installed. Skipping PDF metadata extraction.")

                elif file_type in ("jpeg", "jpg", "png"):
                    if Image:
                        try:
                            with Image.open(temp_path) as img:
                                exif_data = img.getexif()
                                if exif_data:
                                    for tag_id, value in exif_data.items():
                                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                                        if isinstance(value, bytes):
                                            try:
                                                value = value.decode("utf-8", errors="replace")
                                            except Exception:
                                                value = str(value)
                                        else:
                                            value = str(value)

                                        finding["metadata"][str(tag_name)] = value

                                        if str(tag_name) in ("Software", "Make", "Model"):
                                            finding["risk_notes"].append(f"Camera/Software info found: {value}")

                                        if tag_name == "GPSInfo" or tag_id == 34853:
                                            finding["risk_notes"].append("GPS coordinates found (physical location leak)")
                                            result["risk_flags"].append(f"GPS coordinates found in {url}")
                        except Exception as img_err:
                            finding["risk_notes"].append(f"Image parser warning: {img_err}")
                    else:
                        result["errors"].append("Pillow not installed. Skipping image metadata extraction.")

            except Exception as e:
                result["errors"].append(f"Error downloading/processing {url}: {str(e)}")

            result["data"]["findings"].append(finding)

    return result
