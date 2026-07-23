import hashlib
import re
from typing import Any, Dict, List, Optional


class FileAnalyzer:
    """
    Analyzes uploaded files and images for security investigation.
    Extracts SHA256/MD5 hashes, IP addresses, URLs, and log telemetry.
    """

    def analyze(self, filename: str, content_bytes: bytes) -> Dict[str, Any]:
        md5_hash = hashlib.md5(content_bytes).hexdigest()
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        file_size = len(content_bytes)

        # Detect file type extension
        ext = filename.split('.')[-1].lower() if '.' in filename else 'unknown'
        is_image = ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp']
        is_log_or_text = ext in ['txt', 'log', 'csv', 'json', 'xml', 'yml', 'yaml'] or not is_image

        extracted_ips = []
        extracted_urls = []
        extracted_hashes = []
        text_snippet = ""

        if is_log_or_text:
            try:
                text_content = content_bytes.decode('utf-8', errors='ignore')
                text_snippet = text_content[:500]

                # Extract IPs
                extracted_ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text_content)))
                # Extract URLs
                extracted_urls = list(set(re.findall(r'https?://[^\s"\'>]+', text_content)))
                # Extract hashes inside text
                extracted_hashes = list(set(re.findall(r'\b[a-fA-F0-9]{32,64}\b', text_content)))
            except Exception as e:
                text_snippet = f"Binary content analysis error: {e}"

        # Build primary indicator to trigger VirusTotal / SIEM
        primary_indicator = sha256_hash
        if extracted_ips:
            primary_indicator = extracted_ips[0]

        return {
            "filename": filename,
            "file_type": "Image Screenshot" if is_image else f"{ext.upper()} File",
            "size_bytes": file_size,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "extracted_ips": extracted_ips[:5],
            "extracted_urls": extracted_urls[:5],
            "extracted_hashes": extracted_hashes[:5],
            "snippet": text_snippet[:200] if text_snippet else "Binary malware sample or image uploaded.",
            "primary_indicator": primary_indicator,
            "recommendation": f"File hash {sha256_hash[:16]}... submitted for VirusTotal threat intelligence scan."
        }
