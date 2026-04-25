"""
Logging and audit trail management
"""

import logging
from pathlib import Path
from datetime import datetime
import json


def setup_logger(name):
    """Configure logger with file and console handlers"""
    logger = logging.getLogger(name)
    
    if logger.handlers:
        return logger
    
    logger.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    
    # File handler
    log_dir = Path.home() / '.dfat' / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    
    file_handler = logging.FileHandler(
        log_dir / f"dfat_{datetime.now().strftime('%Y%m%d')}.log"
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger


class AuditLogger:
    """Audit trail for chain-of-custody"""
    
    def __init__(self, audit_file: Path):
        self.audit_file = audit_file
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)
    
    def log_action(self, action: str, actor: str, target: str, details: dict = None):
        """Log an action to audit trail"""
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'actor': actor,
            'target': target,
            'details': details or {}
        }
        
        with open(self.audit_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def get_audit_trail(self):
        """Retrieve audit trail"""
        if not self.audit_file.exists():
            return []
        
        entries = []
        with open(self.audit_file, 'r') as f:
            for line in f:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        
        return entries
