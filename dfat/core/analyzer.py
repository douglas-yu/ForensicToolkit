"""
Forensic analysis engine for evidence correlation and finding generation
"""

import uuid
from datetime import datetime
from typing import List, Dict
from dfat.models.forensic_result import (
    ForensicFinding, ForensicAnalysisReport, FindingSeverity, FindingType
)
from dfat.models.evidence import ForensicCase
from dfat.utils.logger import setup_logger

logger = setup_logger(__name__)


class ForensicAnalyzer:
    """Main forensic analysis engine"""
    
    # Known malicious IOCs (in production, load from threat intelligence feeds)
    MALICIOUS_PROCESSES = {
        'mimikatz.exe': {'severity': FindingSeverity.CRITICAL, 'description': 'Credential dumping tool'},
        'psexec.exe': {'severity': FindingSeverity.HIGH, 'description': 'Remote execution tool'},
        'nc.exe': {'severity': FindingSeverity.MEDIUM, 'description': 'Netcat networking tool'},
    }
    
    SUSPICIOUS_PATHS = {
        '/tmp': {'severity': FindingSeverity.MEDIUM},
        '/var/tmp': {'severity': FindingSeverity.MEDIUM},
        'C:\\Users\\Public': {'severity': FindingSeverity.MEDIUM},
    }
    
    SUSPICIOUS_PORTS = {
        4444: {'name': 'Metasploit', 'severity': FindingSeverity.HIGH},
        5555: {'name': 'Android Debug', 'severity': FindingSeverity.MEDIUM},
        6666: {'name': 'IRC', 'severity': FindingSeverity.MEDIUM},
        8888: {'name': 'Proxy', 'severity': FindingSeverity.LOW},
    }
    
    def __init__(self):
        pass
    
    def analyze_case(self, case: ForensicCase, analyst: str) -> ForensicAnalysisReport:
        """Perform complete forensic analysis on a case"""
        report = ForensicAnalysisReport(
            report_id=str(uuid.uuid4()),
            case_id=case.case_id,
            analysis_start=datetime.now(),
            analysis_end=datetime.now(),
            analyst=analyst,
        )
        
        logger.info(f"Starting analysis for case: {case.case_id}")
        
        # Run analysis modules
        self._analyze_processes(case, report)
        self._analyze_network(case, report)
        self._analyze_files(case, report)
        self._analyze_logs(case, report)
        self._analyze_timeline(case, report)
        
        # Calculate final risk score
        report.analysis_end = datetime.now()
        report.calculate_risk_score()
        
        logger.info(f"Analysis complete. Risk Score: {report.risk_score:.1f}")
        
        return report
    
    def _analyze_processes(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze process evidence"""
        logger.debug("Analyzing processes...")
        
        for process in case.processes:
            # Check for known malicious processes
            if process.name in self.MALICIOUS_PROCESSES:
                ioc = self.MALICIOUS_PROCESSES[process.name]
                finding = ForensicFinding(
                    finding_id=str(uuid.uuid4()),
                    finding_type=FindingType.IOC_MATCH,
                    severity=ioc['severity'],
                    title=f"Known Malicious Process: {process.name}",
                    description=ioc['description'],
                    evidence_id=process.name,
                    confidence=0.95,
                    timestamp=datetime.now(),
                    details={
                        'process_name': process.name,
                        'pid': process.pid,
                        'path': process.binary_path,
                        'command_line': process.command_line,
                    },
                    remediation=f"Terminate process {process.pid} and investigate execution context."
                )
                report.findings.append(finding)
            
            # Detect privilege escalation patterns
            if process.user not in ['root', 'system', 'administrator']:
                if any(conn for conn in process.connections if conn.get('remote_port') in [445, 3389]):
                    finding = ForensicFinding(
                        finding_id=str(uuid.uuid4()),
                        finding_type=FindingType.PRIVILEGE_ESCALATION,
                        severity=FindingSeverity.HIGH,
                        title=f"Potential Privilege Escalation: {process.name}",
                        description="Non-privileged process connecting to admin/RDP ports",
                        evidence_id=process.name,
                        confidence=0.75,
                        timestamp=datetime.now(),
                        details={
                            'process_name': process.name,
                            'user': process.user,
                            'connections': process.connections,
                        }
                    )
                    report.findings.append(finding)
    
    def _analyze_network(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze network evidence"""
        logger.debug("Analyzing network connections...")
        
        for conn in case.networks:
            # Check for suspicious ports
            if conn.remote_port in self.SUSPICIOUS_PORTS:
                port_info = self.SUSPICIOUS_PORTS[conn.remote_port]
                finding = ForensicFinding(
                    finding_id=str(uuid.uuid4()),
                    finding_type=FindingType.ANOMALOUS_BEHAVIOR,
                    severity=port_info['severity'],
                    title=f"Suspicious Port Connection: {conn.remote_port}",
                    description=f"{port_info['name']} - {conn.process_name} connecting to {conn.remote_address}:{conn.remote_port}",
                    evidence_id=f"{conn.process_name}:{conn.remote_port}",
                    confidence=0.80,
                    timestamp=datetime.now(),
                    details={
                        'process': conn.process_name,
                        'pid': conn.pid,
                        'remote_address': conn.remote_address,
                        'remote_port': conn.remote_port,
                        'local_address': conn.local_address,
                    }
                )
                report.findings.append(finding)
            
            # Detect data exfiltration patterns
            external_ips = [c for c in case.networks if not self._is_internal_ip(c.remote_address)]
            if len(external_ips) > 10:
                finding = ForensicFinding(
                    finding_id=str(uuid.uuid4()),
                    finding_type=FindingType.DATA_EXFILTRATION,
                    severity=FindingSeverity.HIGH,
                    title="Potential Data Exfiltration",
                    description=f"Multiple external connections detected ({len(external_ips)} unique IPs)",
                    evidence_id="exfil_pattern",
                    confidence=0.70,
                    timestamp=datetime.now(),
                    details={
                        'unique_external_ips': len(external_ips),
                        'connection_count': len(case.networks),
                    }
                )
                report.findings.append(finding)
                break
    
    def _analyze_files(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze file evidence"""
        logger.debug("Analyzing files...")
        
        for file in case.files:
            for suspicious_path in self.SUSPICIOUS_PATHS:
                if suspicious_path in file.path:
                    finding = ForensicFinding(
                        finding_id=str(uuid.uuid4()),
                        finding_type=FindingType.ANOMALOUS_BEHAVIOR,
                        severity=self.SUSPICIOUS_PATHS[suspicious_path]['severity'],
                        title=f"Suspicious File Location: {file.path}",
                        description=f"File found in temporary/suspicious directory",
                        evidence_id=file.path,
                        confidence=0.60,
                        timestamp=datetime.now(),
                        details={
                            'file_path': file.path,
                            'size': file.size,
                            'modified_time': file.modified_time.isoformat(),
                            'hash_sha256': file.hash_sha256,
                        }
                    )
                    report.findings.append(finding)
                    break
    
    def _analyze_logs(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze log evidence"""
        logger.debug("Analyzing logs...")
        
        error_count = sum(1 for log in case.logs if log.level in ['ERROR', 'CRITICAL'])
        if error_count > 50:
            finding = ForensicFinding(
                finding_id=str(uuid.uuid4()),
                finding_type=FindingType.ANOMALOUS_BEHAVIOR,
                severity=FindingSeverity.MEDIUM,
                title="Unusual Error Rate in Logs",
                description=f"{error_count} error/critical events detected",
                evidence_id="log_anomaly",
                confidence=0.65,
                timestamp=datetime.now(),
                details={'error_count': error_count, 'total_logs': len(case.logs)}
            )
            report.findings.append(finding)
    
    def _analyze_timeline(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze event timeline"""
        logger.debug("Analyzing timeline...")
        
        timeline_events = []
        
        for process in case.processes:
            timeline_events.append({
                'timestamp': process.create_time.isoformat(),
                'type': 'process_created',
                'source': process.name,
                'description': f"Process created: {process.name} (PID: {process.pid})"
            })
        
        for conn in case.networks:
            timeline_events.append({
                'timestamp': conn.create_time.isoformat(),
                'type': 'network_connection',
                'source': conn.process_name,
                'description': f"Network connection: {conn.process_name} -> {conn.remote_address}:{conn.remote_port}"
            })
        
        report.timeline = sorted(timeline_events, key=lambda x: x['timestamp'])
    
    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        """Check if IP is internal/private"""
        internal_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
        ]
        try:
            from ipaddress import ip_address, ip_network
            ip_obj = ip_address(ip)
            return any(ip_obj in ip_network(range, strict=False) for range in internal_ranges)
        except:
            return False
