"""
Forensic analysis results models
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any
from enum import Enum


class FindingSeverity(Enum):
    """Finding severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class FindingType(Enum):
    """Type of forensic finding"""
    IOC_MATCH = "ioc_match"
    SUSPICIOUS_PROCESS = "suspicious_process"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PERSISTENCE_MECHANISM = "persistence_mechanism"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass
class ForensicFinding:
    """Single forensic analysis finding"""
    finding_id: str
    finding_type: FindingType
    severity: FindingSeverity
    title: str
    description: str
    evidence_id: str
    confidence: float  # 0-1
    timestamp: datetime
    
    details: Dict[str, Any] = field(default_factory=dict)
    related_artifacts: List[str] = field(default_factory=list)
    remediation: str = None
    references: List[str] = field(default_factory=list)


@dataclass
class ForensicAnalysisReport:
    """Complete forensic analysis report"""
    report_id: str
    case_id: str
    analysis_start: datetime
    analysis_end: datetime
    analyst: str
    
    findings: List[ForensicFinding] = field(default_factory=list)
    risk_score: float = 0.0  # 0-100
    overall_status: str = "unknown"  # clean, suspicious, compromised
    
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    
    def calculate_risk_score(self):
        """Calculate overall risk score"""
        if not self.findings:
            self.risk_score = 0.0
            return
        
        weighted_score = 0
        for finding in self.findings:
            weight = finding.severity.value * finding.confidence
            weighted_score += weight
        
        # Normalize to 0-100
        max_weight = len(self.findings) * 5.0  # Max severity * confidence
        self.risk_score = min((weighted_score / max_weight) * 100, 100.0)
        
        # Determine overall status
        if self.risk_score >= 70:
            self.overall_status = "compromised"
        elif self.risk_score >= 40:
            self.overall_status = "suspicious"
        else:
            self.overall_status = "clean"
