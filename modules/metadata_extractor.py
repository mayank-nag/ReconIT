import os
import tempfile
import requests
from typing import Dict, Any, List
from urllib.parse import urlparse

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    from PIL import Image, ExifTags
except ImportError:
    Image = None


def run(files: List[Dict[str, str]], timeout: int = 15) -> Dict[str, Any]:
    """
    Downloads publicly linked documents/images and extracts hidden metadata.
    
    Args:
        files: List of dicts like [{'url': '...', 'type': 'pdf'}, ...]
        timeout: Timeout for downloading each file in seconds.
        
    Returns:
        Dict containing 'data', 'risk_flags', and 'errors'.
    """
    result = {
        'data': {'findings': []},
        'risk_flags': [],
        'errors': []
    }
    
    if not files:
        return result
        
    MAX_FILES = 20
    MAX_SIZE = 10 * 1024 * 1024  # 10 MB
    
    files_to_process = files[:MAX_FILES]
    
    with tempfile.TemporaryDirectory() as temp_dir:
        for file_info in files_to_process:
            url = file_info.get('url')
            file_type = file_info.get('type', '').lower()
            
            if not url:
                continue
                
            finding = {
                'url': url,
                'type': file_type,
                'metadata': {},
                'risk_notes': []
            }
            
            try:
                # 1. Download file
                response = requests.get(url, stream=True, timeout=timeout)
                response.raise_for_status()
                
                # Check size limit from headers if available
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) > MAX_SIZE:
                    raise ValueError("File size exceeds 10MB limit")
                
                parsed_url = urlparse(url)
                filename = os.path.basename(parsed_url.path)
                if not filename:
                    filename = "temp_file"
                
                temp_path = os.path.join(temp_dir, filename)
                
                downloaded_size = 0
                with open(temp_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            downloaded_size += len(chunk)
                            if downloaded_size > MAX_SIZE:
                                raise ValueError("File size exceeds 10MB limit during download")
                            f.write(chunk)
                
                # 2. Extract metadata based on type
                if file_type == 'pdf':
                    if PyPDF2:
                        with open(temp_path, 'rb') as f:
                            reader = PyPDF2.PdfReader(f)
                            if reader.metadata:
                                meta = reader.metadata
                                author = meta.get('/Author')
                                creator = meta.get('/Creator')
                                producer = meta.get('/Producer')
                                creation_date = meta.get('/CreationDate')
                                
                                if author:
                                    finding['metadata']['author'] = str(author)
                                    finding['risk_notes'].append(f"Author name found: {author} (potential employee enumeration)")
                                    result['risk_flags'].append(f"PDF Author found in {url}")
                                if creator:
                                    finding['metadata']['creator'] = str(creator)
                                    finding['risk_notes'].append(f"Software/tool info found: {creator}")
                                if producer:
                                    finding['metadata']['producer'] = str(producer)
                                    finding['risk_notes'].append(f"Software/tool info found: {producer}")
                                if creation_date:
                                    finding['metadata']['creation_date'] = str(creation_date)
                    else:
                        result['errors'].append("PyPDF2 not installed. Skipping PDF metadata extraction.")
                        
                elif file_type in ['jpeg', 'jpg', 'png']:
                    if Image:
                        try:
                            with Image.open(temp_path) as img:
                                exif_data = img.getexif()
                                if exif_data:
                                    for tag_id, value in exif_data.items():
                                        tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                                        if isinstance(value, bytes):
                                            try:
                                                value = value.decode('utf-8', errors='replace')
                                            except Exception:
                                                value = str(value)
                                        else:
                                            value = str(value)
                                            
                                        finding['metadata'][str(tag_name)] = value
                                        
                                        if str(tag_name) in ['Software', 'Make', 'Model']:
                                            finding['risk_notes'].append(f"Software/tool info found: {value}")
                                            
                                        # Basic check for GPSInfo (tag 34853 or explicitly named)
                                        if tag_name == 'GPSInfo' or tag_id == 34853:
                                            finding['risk_notes'].append("GPS coordinates found (physical location leak)")
                                            result['risk_flags'].append(f"GPS coordinates found in {url}")
                        except Exception as e:
                            result['errors'].append(f"Error reading image {url}: {str(e)}")
                    else:
                        result['errors'].append("Pillow not installed. Skipping image metadata extraction.")
                
            except requests.Timeout:
                result['errors'].append(f"Timeout downloading {url}")
            except Exception as e:
                result['errors'].append(f"Error processing {url}: {str(e)}")
                
            result['data']['findings'].append(finding)
            
    return result
