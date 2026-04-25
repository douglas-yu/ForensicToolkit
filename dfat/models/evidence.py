"""
Evidence data models
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any
from enum import Enum


class EvidenceType(Enum):
    """Types of forensic evidence"""
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    LOG = "log"
    REGISTRY = "registry"
    MEMORY = "memory"
    SYSTEM_INFO = "system_info"


@dataclass
class ProcessEvidence:
    """Process forensic evidence"""
    pid: int
    name: str
    command_line: str
    user: str
    create_time: datetime
    memory_mb: float
    cpu_percent: float
    parent_pid: int = None
    hash_md5: str = None
    hash_sha256: str = None
    binary_path: str = None
    status: str = "running"
    connections: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class NetworkEvidence:
    """Network connection evidence"""
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: int
    process_name: str
    create_time: datetime


@dataclass
class FileEvidence:
    """File system evidence"""
    path: str
    size: int
    created_time: datetime
    modified_time: datetime
    accessed_time: datetime
    owner: str
    permissions: str
    hash_md5: str = None
    hash_sha256: str = None
    is_system: bool = False
    is_hidden: bool = False


@dataclass
class LogEvidence:
    """System log evidence"""
    log_type: str  # syslog, eventlog, application
    timestamp: datetime
    source: str
    event_id: int
    level: str  # INFO, WARNING, ERROR, CRITICAL
    message: str
    user: str = None
    computer: str = None


@dataclass
class SystemInfoEvidence:
    """System information evidence"""
    hostname: str
    os_name: str
    os_version: str
    os_build: str
    architecture: str
    cpu_count: int
    memory_mb: int
    uptime_seconds: int
    timezone: str
    local_time: datetime
    username: str


@dataclass
class ForensicCase:
    """Container for a forensic investigation case"""
    case_id: str
    case_name: str
    agent_id: str
    target_host: str
    collection_start: datetime
    collection_end: datetime = None
    status: str = "in_progress"  # in_progress, completed, failed
    
    processes: List[ProcessEvidence] = field(default_factory=list)
    networks: List[NetworkEvidence] = field(default_factory=list)
    files: List[FileEvidence] = field(default_factory=list)
    logs: List[LogEvidence] = field(default_factory=list)
    system_info: SystemInfoEvidence = None
    
    collection_errors: List[str] = field(default_factory=list)
