"""
Configuration management for DFAT
"""

import json
import os
from pathlib import Path
from typing import Dict, Any


class Config:
    """Central configuration manager"""
    
    def __init__(self):
        self.config_dir = Path.home() / '.dfat'
        self.config_dir.mkdir(exist_ok=True)
        
        self.config_file = self.config_dir / 'config.json'
        self.certs_dir = self.config_dir / 'certs'
        self.certs_dir.mkdir(exist_ok=True)
        
        self.evidence_dir = self.config_dir / 'evidence'
        self.evidence_dir.mkdir(exist_ok=True)
        
        self.logs_dir = self.config_dir / 'logs'
        self.logs_dir.mkdir(exist_ok=True)
        
        self.db_file = self.config_dir / 'dfat.db'
        
        self.defaults = {
            'server_host': '0.0.0.0',
            'server_port': 9443,
            'server_timeout': 30,
            'max_agents': 100,
            'evidence_retention_days': 30,
            'enable_ssl': True,
            'ssl_cert_path': str(self.certs_dir / 'server.crt'),
            'ssl_key_path': str(self.certs_dir / 'server.key'),
            'log_level': 'INFO',
            'database': str(self.db_file),
            'theme': 'dark',
        }
        
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        else:
            self.save_config(self.defaults)
            return self.defaults.copy()
    
    def save_config(self, data: Dict[str, Any]) -> None:
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get(self, key: str, default=None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value"""
        self.config[key] = value
        self.save_config(self.config)
    
    @property
    def server_url(self) -> str:
        """Get server URL"""
        protocol = 'https' if self.get('enable_ssl') else 'http'
        host = self.get('server_host', '0.0.0.0')
        port = self.get('server_port', 9443)
        if host == '0.0.0.0':
            host = 'localhost'
        return f"{protocol}://{host}:{port}"
