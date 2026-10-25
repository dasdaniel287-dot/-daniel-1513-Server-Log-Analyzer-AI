"""
File Ingestion Validation
Protects against path traversal, oversized payloads, and malicious executable extensions.
"""

import os
import re
from typing import Tuple

ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".csv", ".syslog", ".out"}
DANGEROUS_EXTENSIONS = {".exe", ".sh", ".bin", ".py", ".js", ".bat", ".cmd", ".php", ".vbs"}


def sanitize_filename(filename: str) -> str:
    """Strip directory paths and unsafe characters to prevent path traversal."""
    base = os.path.basename(filename)
    # Remove null bytes and path components
    cleaned = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', base)
    if not cleaned:
        cleaned = "unnamed_log.log"
    return cleaned


def validate_file_metadata(filename: str, size_bytes: int, max_size_bytes: int) -> Tuple[bool, str]:
    """Validate uploaded file size and extension boundaries."""
    if size_bytes > max_size_bytes:
        return False, f"File size ({size_bytes} bytes) exceeds maximum limit ({max_size_bytes} bytes)"
    
    _, ext = os.path.splitext(filename.lower())
    if ext in DANGEROUS_EXTENSIONS:
        return False, f"Executable file extension '{ext}' is forbidden for security"
        
    return True, "Valid"
