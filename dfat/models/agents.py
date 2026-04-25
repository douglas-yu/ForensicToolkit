"""
Agent data models
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any
from enum import Enum


class AgentStatus(Enum):
    """Agent status values"""
    OFFLINE = "offline"
    CONNECTING = "connecting"
    ONLINE = "online"
    COLLECTING = "collecting"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class RemoteAgent:
    """Remote forensic agent"""
    agent_id: str
    hostname: str
    ip_address: str
    port: int
    os_type: str  # windows, linux, macos
    os_version: str
    
    status: AgentStatus = AgentStatus.OFFLINE
    last_seen: datetime = None
    first_deployed: datetime = None
    
    # Connection details
    ssh_user: str = None
    ssh_port: int = 22
    
    # Collection configuration
    collection_interval: int = 3600  # seconds
    enabled_collectors: Dict[str, bool] = field(default_factory=lambda: {
        'processes': True,
        'network': True,
        'files': True,
        'logs': True,
        'registry': False,  # Windows only
        'memory': False,
    })
    
    # Metadata
    tags: Dict[str, str] = field(default_factory=dict)
    deployment_errors: list = field(default_factory=list)


@dataclass
class AgentDeployment:
    """Agent deployment record"""
    deployment_id: str
    agent_id: str
    target_host: str
    target_port: int
    ssh_user: str
    
    status: str = "pending"  # pending, in_progress, success, failed
    start_time: datetime = None
    end_time: datetime = None
    
    deployment_method: str = "ssh"  # ssh, winrm, manual
    deployment_script: str = None
    
    error_message: str = None
    deployment_log: str = ""
