"""
Utility helper functions
"""

import hashlib
from pathlib import Path
from typing import Optional
import re


def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate hash of a file"""
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        return None


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private"""
    internal_ranges = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^::1$',
        r'^fe80:',
    ]
    
    for pattern in internal_ranges:
        if re.match(pattern, ip):
            return True
    return False


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable size"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations"""
    import string
    valid_chars = f"-_.() {string.ascii_letters}{string.digits}"
    return ''.join(c for c in filename if c in valid_chars)
