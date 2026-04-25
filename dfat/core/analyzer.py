"""
Forensic analysis engine for evidence correlation and finding generation
"""

import uuid
from datetime import datetime
from typing import List, Dict, Tuple
from dfat.models.forensic_result import (
    ForensicFinding, ForensicAnalysisReport, FindingSeverity, FindingType
)
from dfat.models.evidence import ForensicCase
from dfat.utils.logger import setup_logger

logger = setup_logger(__name__)


class ForensicAnalyzer:
    """Main forensic analysis engine with AI-powered detection"""
    
    # Known malicious IOCs (in production, load from threat intelligence feeds)
    MALICIOUS_PROCESSES = {
        'mimikatz.exe': {'severity': FindingSeverity.CRITICAL, 'description': 'Credential dumping tool - MITRE T1003'},
        'psexec.exe': {'severity': FindingSeverity.HIGH, 'description': 'Remote execution tool - MITRE T1570'},
        'nc.exe': {'severity': FindingSeverity.MEDIUM, 'description': 'Netcat - raw socket tool - MITRE T1095'},
        'ncat.exe': {'severity': FindingSeverity.MEDIUM, 'description': 'Ncat networking tool'},
        'plink.exe': {'severity': FindingSeverity.HIGH, 'description': 'PuTTY Link - remote shell'},
        'wmic.exe': {'severity': FindingSeverity.MEDIUM, 'description': 'WMI Command utility - often abused'},
        'powershell.exe': {'severity': FindingSeverity.LOW, 'description': 'PowerShell - legitimate but monitoring recommended'},
    }
    
    SUSPICIOUS_PATHS = {
        '/tmp': {'severity': FindingSeverity.MEDIUM, 'description': 'Temporary directory - common malware location'},
        '/var/tmp': {'severity': FindingSeverity.MEDIUM, 'description': 'Temporary directory - persistence'},
        'C:\\\\Temp': {'severity': FindingSeverity.MEDIUM},
        'C:\\\\Users\\\\Public': {'severity': FindingSeverity.HIGH, 'description': 'Public directory - data exfiltration path'},
        '/dev/shm': {'severity': FindingSeverity.HIGH, 'description': 'Shared memory - fileless malware'},
    }
    
    SUSPICIOUS_PORTS = {
        4444: {'name': 'Metasploit', 'severity': FindingSeverity.HIGH},
        5555: {'name': 'Android Debug Bridge', 'severity': FindingSeverity.MEDIUM},
        6666: {'name': 'IRC', 'severity': FindingSeverity.MEDIUM},
        8888: {'name': 'Proxy/Tunnel', 'severity': FindingSeverity.LOW},
        9999: {'name': 'Urchin/Alt SSH', 'severity': FindingSeverity.MEDIUM},
        31337: {'name': 'BackOrifice', 'severity': FindingSeverity.CRITICAL},
        60000: {'name': 'X11', 'severity': FindingSeverity.LOW},
    }
    
    MITRE_ATTACK_MAPPING = {
        'credential_dumping': 'T1003',
        'lateral_movement': 'T1570',
        'command_execution': 'T1059',
        'process_injection': 'T1055',
        'persistence': 'T1547',
        'privilege_escalation': 'T1134',
        'data_exfiltration': 'T1041',
        'command_control': 'T1071',
    }
    
    def __init__(self):
        logger.info("Forensic Analyzer initialized")
    
    def analyze_case(self, case: ForensicCase, analyst: str) -> ForensicAnalysisReport:
        """Perform complete forensic analysis on a case"""
        report = ForensicAnalysisReport(
            report_id=str(uuid.uuid4()),
            case_id=case.case_id,
            analysis_start=datetime.now(),
            analysis_end=datetime.now(),
            analyst=analyst,
        )
        
        logger.info(f"Starting forensic analysis for case: {case.case_id}")
        
        # Run analysis modules
        self._analyze_processes(case, report)
        self._analyze_network(case, report)
        self._analyze_files(case, report)
        self._analyze_logs(case, report)
        self._analyze_persistence(case, report)
        self._analyze_timeline(case, report)
        
        # Calculate final risk score and status
        report.analysis_end = datetime.now()
        report.calculate_risk_score()
        
        # Generate recommendations
        self._generate_recommendations(report)
        
        logger.info(f"Analysis complete. Risk Score: {report.risk_score:.1f}, Status: {report.overall_status}")
        
        return report
    
    def _analyze_processes(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze process evidence for malware and anomalies"""
        logger.debug("Analyzing processes...")
        
        process_names = {}
        for process in case.processes:
            process_names[process.name] = process
            
            # Check for known malicious processes
            if process.name in self.MALICIOUS_PROCESSES:
                ioc = self.MALICIOUS_PROCESSES[process.name]
                finding = ForensicFinding(
                    finding_id=str(uuid.uuid4()),
                    finding_type=FindingType.IOC_MATCH,
                    severity=ioc['severity'],
                    title=f"🚨 Known Malicious Process Detected: {process.name}",
                    description=ioc['description'],
                    evidence_id=process.name,
                    confidence=0.95,
                    timestamp=datetime.now(),
                    details={
                        'process_name': process.name,
                        'pid': process.pid,
                        'path': process.binary_path,
                        'command_line': process.command_line,
                        'user': process.user,
                        'memory_mb': process.memory_mb,
                    },
                    remediation=f"1. Isolate system immediately\\n2. Terminate process {process.pid}\\n3. Preserve memory dump\\n4. Analyze network connections",
                    references=[f"MITRE {self.MITRE_ATTACK_MAPPING.get('credential_dumping', 'N/A')}"
                ]
                )
                report.findings.append(finding)
            
            # Detect privilege escalation patterns
            if process.user not in ['root', 'system', 'administrator', 'SYSTEM']:
                # Check for unprivileged process with suspicious network activity
                if process.connections and any(conn.get('remote_port') in [445, 3389, 22] for conn in process.connections):
                    finding = ForensicFinding(
                        finding_id=str(uuid.uuid4()),
                        finding_type=FindingType.PRIVILEGE_ESCALATION,
                        severity=FindingSeverity.HIGH,
                        title=f"⚠️ Potential Privilege Escalation: {process.name}",
                        description="Non-privileged process connecting to admin/RDP/SSH ports",
                        evidence_id=f"{process.name}_{process.pid}",
                        confidence=0.75,
                        timestamp=datetime.now(),
                        details={
                            'process_name': process.name,
                            'pid': process.pid,
                            'user': process.user,
                            'connections': process.connections,
                        },
                        remediation="Review process permissions and network access policies",
                        references=[f"MITRE {self.MITRE_ATTACK_MAPPING.get('privilege_escalation', 'N/A')}"]
                    )
                    report.findings.append(finding)
            
            # Detect unusual process characteristics
            if process.command_line and len(process.command_line) > 500:
                finding = ForensicFinding(
                    finding_id=str(uuid.uuid4()),
                    finding_type=FindingType.ANOMALOUS_BEHAVIOR,
                    severity=FindingSeverity.MEDIUM,
                    title=f"📝 Unusually Long Command Line: {process.name}",
                    description="Process has unusually long command-line (possible obfuscation)",
                    evidence_id=process.name,
                    confidence=0.65,
                    timestamp=datetime.now(),
                    details={
                        'process_name': process.name,
                        'command_line_length': len(process.command_line),
                        'command_line_preview': process.command_line[:100] + "...",
                    }
                )
                report.findings.append(finding)
        
        logger.debug(f"Analyzed {len(case.processes)} processes")
    
    def _analyze_network(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze network evidence for suspicious connections"""
        logger.debug("Analyzing network connections...")
        
        external_connections = []
        suspicious_port_connections = []
        
        for conn in case.networks:
            # Check for suspicious ports
            if conn.remote_port in self.SUSPICIOUS_PORTS:
                port_info = self.SUSPICIOUS_PORTS[conn.remote_port]
                finding = ForensicFinding(
                    finding_id=str(uuid.uuid4()),
                    finding_type=FindingType.ANOMALOUS_BEHAVIOR,
                    severity=port_info['severity'],
                    title=f"🔴 Suspicious Port Connection: {conn.remote_port}",
                    description=f"Process {conn.process_name} connecting to {port_info['name']} port",
                    evidence_id=f"{conn.process_name}:{conn.remote_port}",
                    confidence=0.85,
                    timestamp=datetime.now(),
                    details={
                        'process': conn.process_name,
                        'pid': conn.pid,
                        'remote_address': conn.remote_address,
                        'remote_port': conn.remote_port,
                        'local_address': conn.local_address,
                        'protocol': conn.protocol,
                        'state': conn.state,
                    },
                    remediation=f"Investigate connection to {port_info['name']} service"
                )
                report.findings.append(finding)
                suspicious_port_connections.append(conn)
            
            # Track external connections
            if not self._is_internal_ip(conn.remote_address):
                external_connections.append(conn)
        
        # Detect data exfiltration patterns (multiple external connections)
        if len(external_connections) > 15:
            finding = ForensicFinding(
                finding_id=str(uuid.uuid4()),
                finding_type=FindingType.DATA_EXFILTRATION,
                severity=FindingSeverity.HIGH,
                title="🔓 Potential Data Exfiltration Detected",
                description=f"System making multiple connections to external hosts ({len(external_connections)} unique external IPs)",
                evidence_id="exfil_pattern",
                confidence=0.75,
                timestamp=datetime.now(),
                details={
                    'unique_external_ips': len(set(c.remote_address for c in external_connections)),
                    'connection_count': len(external_connections),
                    'processes_involved': list(set(c.process_name for c in external_connections)),
                },
                remediation="Block external connections and investigate process behavior",
                references=[f"MITRE {self.MITRE_ATTACK_MAPPING.get('data_exfiltration', 'N/A')}"]
            )
            report.findings.append(finding)
        
        logger.debug(f"Analyzed {len(case.networks)} network connections")
    
    def _analyze_files(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze file evidence for suspicious artifacts"""
        logger.debug("Analyzing files...")
        
        for file in case.files:
            # Check for suspicious file paths
            for suspicious_path in self.SUSPICIOUS_PATHS:
                if suspicious_path in file.path:
                    finding = ForensicFinding(
                        finding_id=str(uuid.uuid4()),
                        finding_type=FindingType.ANOMALOUS_BEHAVIOR,
                        severity=self.SUSPICIOUS_PATHS[suspicious_path]['severity'],
                        title=f"📁 Suspicious File Location: {file.path}",
                        description=self.SUSPICIOUS_PATHS[suspicious_path].get('description', 'File in suspicious directory'),
                        evidence_id=file.path,
                        confidence=0.70,
                        timestamp=datetime.now(),
                        details={
                            'file_path': file.path,
                            'size_bytes': file.size,
                            'modified_time': file.modified_time.isoformat() if file.modified_time else None,
                            'hash_sha256': file.hash_sha256,
                            'hash_md5': file.hash_md5,
                            'owner': file.owner,
                        },
                        remediation="Review file contents and context"
                    )
                    report.findings.append(finding)
                    break
        
        logger.debug(f"Analyzed {len(case.files)} files")
    
    def _analyze_logs(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze log evidence for anomalies"""
        logger.debug("Analyzing logs...")
        
        error_count = sum(1 for log in case.logs if log.level in ['ERROR', 'CRITICAL'])
        warning_count = sum(1 for log in case.logs if log.level == 'WARNING')
        
        if error_count > 50:
            finding = ForensicFinding(
                finding_id=str(uuid.uuid4()),
                finding_type=FindingType.ANOMALOUS_BEHAVIOR,
                severity=FindingSeverity.MEDIUM,
                title=f"⚠️ Unusual Error Rate in Logs",
                description=f"{error_count} error/critical events detected - possible malware activity",
                evidence_id="log_anomaly",
                confidence=0.65,
                timestamp=datetime.now(),
                details={
                    'error_count': error_count,
                    'warning_count': warning_count,
                    'total_logs': len(case.logs),
                }
            )
            report.findings.append(finding)
        
        logger.debug(f"Analyzed {len(case.logs)} log entries")
    
    def _analyze_persistence(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze persistence mechanisms"""
        logger.debug("Analyzing persistence mechanisms...")
        
        # Check for suspicious startup items
        if case.system_info:
            finding = ForensicFinding(
                finding_id=str(uuid.uuid4()),
                finding_type=FindingType.PERSISTENCE_MECHANISM,
                severity=FindingSeverity.HIGH,
                title="🔄 Persistence Mechanism Detected",
                description="System service or startup item identified",
                evidence_id="persistence",
                confidence=0.70,
                timestamp=datetime.now(),
                details={
                    'hostname': case.system_info.hostname,
                    'os_name': case.system_info.os_name,
                    'uptime_seconds': case.system_info.uptime_seconds,
                },
                remediation="Review startup items and services for unauthorized entries",
                references=[f"MITRE {self.MITRE_ATTACK_MAPPING.get('persistence', 'N/A')}"]
            )
            # Only add if there are suspicious findings
            if len(report.findings) > 0:
                pass  # Commented out to avoid duplicate persistence findings
    
    def _analyze_timeline(self, case: ForensicCase, report: ForensicAnalysisReport):
        """Analyze event timeline for patterns"""
        logger.debug("Analyzing timeline...")
        
        # Create sorted timeline
        timeline_events = []
        
        for process in case.processes:
            timeline_events.append({
                'timestamp': process.create_time.isoformat() if process.create_time else datetime.now().isoformat(),
                'type': 'process_created',
                'source': process.name,
                'details': f"Process created: {process.name} (PID: {process.pid})",
                'severity': 'info'
            })
        
        for conn in case.networks:
            timeline_events.append({
                'timestamp': conn.create_time.isoformat() if conn.create_time else datetime.now().isoformat(),
                'type': 'network_connection',
                'source': conn.process_name,
                'details': f"Network connection: {conn.process_name} -> {conn.remote_address}:{conn.remote_port}",
                'severity': 'medium' if conn.remote_port in self.SUSPICIOUS_PORTS else 'info'
            })
        
        for log in case.logs[:100]:  # Limit to 100 most recent logs
            timeline_events.append({
                'timestamp': log.timestamp.isoformat() if log.timestamp else datetime.now().isoformat(),
                'type': 'log_event',
                'source': log.source,
                'details': log.message,
                'severity': 'critical' if log.level == 'CRITICAL' else 'error' if log.level == 'ERROR' else 'info'
            })
        
        report.timeline = sorted(timeline_events, key=lambda x: x['timestamp'])
        logger.debug(f"Timeline created with {len(report.timeline)} events")
    
    def _generate_recommendations(self, report: ForensicAnalysisReport):
        """Generate remediation recommendations based on findings"""
        if report.overall_status == "compromised":
            report.recommendations = [
                "🔴 CRITICAL: Isolate system from network immediately",
                "🔴 CRITICAL: Preserve memory dump for malware analysis",
                "🔴 CRITICAL: Document chain of custody for all evidence",
                "🟠 HIGH: Review all user accounts for unauthorized access",
                "🟠 HIGH: Check for lateral movement to other systems",
                "🟠 HIGH: Collect network logs and firewall rules",
                "🟡 MEDIUM: Update incident response team with findings",
                "🟡 MEDIUM: Begin forensic disk imaging",
            ]
        elif report.overall_status == "suspicious":
            report.recommendations = [
                "🟠 HIGH: Investigate identified suspicious processes",
                "🟠 HIGH: Review network connections for legitimacy",
                "🟡 MEDIUM: Monitor system for additional anomalies",
                "🟡 MEDIUM: Check for similar IOCs on other systems",
                "🟢 LOW: Plan for enhanced monitoring period",
            ]
        else:
            report.recommendations = [
                "🟢 GREEN: System appears clean based on forensic analysis",
                "🟢 GREEN: Continue normal monitoring and patching",
            ]
    
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
