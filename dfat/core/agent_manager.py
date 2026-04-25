"""
Agent deployment and lifecycle management
"""

import os
import uuid
import socket
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import json

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

from dfat.models.agents import RemoteAgent, AgentDeployment, AgentStatus
from dfat.network.crypto import CertificateManager
from dfat.utils.logger import setup_logger

logger = setup_logger(__name__)


class AgentManager:
    """Manages remote agent deployment and lifecycle"""
    
    def __init__(self, config):
        self.config = config
        self.agents: Dict[str, RemoteAgent] = {}
        self.ssh_clients: Dict[str, paramiko.SSHClient] = {} if PARAMIKO_AVAILABLE else {}
        self.cert_manager = CertificateManager(config.certs_dir)
    
    def generate_agent_deployment_script(self, agent_id: str, agent_config: Dict) -> str:
        """Generate agent deployment script"""
        script = f"""#!/bin/bash
set -e

# Digital Forensics Agent Deployment
# Agent ID: {agent_id}
# Deployment Date: {datetime.now().isoformat()}

AGENT_DIR="/opt/dfat-agent"
AGENT_USER="dfat-agent"

# Create agent user (if not exists)
if ! id "$AGENT_USER" &>/dev/null; then
    useradd -r -s /bin/false $AGENT_USER 2>/dev/null || true
fi

# Create agent directory
mkdir -p $AGENT_DIR
cd $AGENT_DIR

# Create agent configuration
cat > config.json << 'EOF'
{json.dumps(agent_config, indent=2)}
EOF

# Create systemd service
cat > /etc/systemd/system/dfat-agent.service << 'SEOF'
[Unit]
Description=DFAT Forensic Agent
After=network.target

[Service]
Type=simple
User=$AGENT_USER
ExecStart=/usr/bin/python3 -m dfat.agents.agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SEOF

# Start agent
systemctl daemon-reload
systemctl enable dfat-agent
systemctl start dfat-agent

echo "Agent deployed successfully: {agent_id}"
"""
        return script
    
    def deploy_agent(self, target_host: str, target_port: int, ssh_user: str, 
                    ssh_password: str = None, ssh_key_path: str = None) -> Tuple[bool, str]:
        """Deploy agent to remote host via SSH"""
        if not PARAMIKO_AVAILABLE:
            return False, "Paramiko library not installed. Install with: pip install paramiko"
        
        agent_id = str(uuid.uuid4())
        deployment_id = str(uuid.uuid4())
        
        try:
            # Connect via SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if ssh_key_path:
                ssh.connect(target_host, port=target_port, username=ssh_user, 
                           key_filename=ssh_key_path, timeout=30)
                logger.info(f"SSH connected to {target_host} with key")
            else:
                ssh.connect(target_host, port=target_port, username=ssh_user, 
                           password=ssh_password, timeout=30)
                logger.info(f"SSH connected to {target_host} with password")
            
            # Generate deployment script
            agent_config = {
                'agent_id': agent_id,
                'server_url': self.config.server_url,
                'ssl_verify': True,
                'collection_interval': 3600,
            }
            
            deploy_script = self.generate_agent_deployment_script(agent_id, agent_config)
            
            # Upload and execute deployment script
            sftp = ssh.open_sftp()
            remote_script = f"/tmp/dfat_deploy_{agent_id}.sh"
            
            with sftp.file(remote_script, 'w') as f:
                f.write(deploy_script)
            
            # Make script executable and run
            ssh.exec_command(f"chmod +x {remote_script}")
            stdin, stdout, stderr = ssh.exec_command(f"bash {remote_script}")
            
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            sftp.close()
            ssh.close()
            
            if exit_code == 0:
                # Create agent record
                agent = RemoteAgent(
                    agent_id=agent_id,
                    hostname=target_host,
                    ip_address=socket.gethostbyname(target_host) if target_host != 'localhost' else '127.0.0.1',
                    port=target_port,
                    os_type="linux",
                    os_version="unknown",
                    status=AgentStatus.ONLINE,
                    first_deployed=datetime.now(),
                    ssh_user=ssh_user,
                    ssh_port=target_port,
                )
                
                self.agents[agent_id] = agent
                logger.info(f"Agent deployed successfully: {agent_id}")
                return True, agent_id
            else:
                logger.error(f"Deployment failed: {error}")
                return False, error
        
        except Exception as e:
            logger.error(f"Agent deployment error: {str(e)}")
            return False, str(e)
    
    def get_agent_status(self, agent_id: str) -> AgentStatus:
        """Get agent status"""
        if agent_id in self.agents:
            agent = self.agents[agent_id]
            agent.last_seen = datetime.now()
            return agent.status
        return AgentStatus.UNKNOWN
    
    def list_agents(self) -> list:
        """List all agents"""
        return list(self.agents.values())
    
    def remove_agent(self, agent_id: str) -> Tuple[bool, str]:
        """Remove agent from remote host"""
        try:
            if agent_id not in self.agents:
                return False, "Agent not found"
            
            agent = self.agents[agent_id]
            
            if not PARAMIKO_AVAILABLE:
                return False, "Paramiko library not installed"
            
            # Stop and remove systemd service
            cleanup_command = """
            systemctl stop dfat-agent || true
            systemctl disable dfat-agent || true
            rm -rf /opt/dfat-agent
            rm -f /etc/systemd/system/dfat-agent.service
            systemctl daemon-reload
            """
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(agent.hostname, port=agent.ssh_port, username=agent.ssh_user, timeout=30)
            
            stdin, stdout, stderr = ssh.exec_command(cleanup_command)
            exit_code = stdout.channel.recv_exit_status()
            
            ssh.close()
            
            if exit_code == 0:
                del self.agents[agent_id]
                logger.info(f"Agent removed: {agent_id}")
                return True, "Agent removed successfully"
            else:
                return False, stderr.read().decode('utf-8')
        
        except Exception as e:
            logger.error(f"Error removing agent: {str(e)}")
            return False, str(e)
