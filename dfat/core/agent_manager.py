"""
Agent deployment and lifecycle management
"""

import os
import uuid
import socket
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import paramiko
import json

from dfat.models.agents import RemoteAgent, AgentDeployment, AgentStatus
from dfat.network.crypto import CertificateManager
from dfat.utils.logger import setup_logger

logger = setup_logger(__name__)


class AgentManager:
    """Manages remote agent deployment and lifecycle"""
    
    def __init__(self, config):
        self.config = config
        self.agents: Dict[str, RemoteAgent] = {}
        self.ssh_clients: Dict[str, paramiko.SSHClient] = {}
        self.cert_manager = CertificateManager(config.certs_dir)
    
    def generate_agent_deployment_script(self, agent_id: str, agent_config: Dict) -> str:
        """Generate agent deployment script for Linux targets"""
        script = f"""#!/bin/bash
set -e

# Digital Forensics Agent Deployment
# Agent ID: {agent_id}
# Deployment Date: {datetime.now().isoformat()}

AGENT_DIR="/opt/dfat-agent"
AGENT_USER="dfat-agent"

echo "[*] DFAT Agent Deployment Started"
echo "[*] Agent ID: {agent_id}"

# Create agent user (if not exists)
if ! id "$AGENT_USER" &>/dev/null; then
    echo "[+] Creating dfat-agent user..."
    useradd -r -s /bin/false $AGENT_USER 2>/dev/null || true
fi

# Create agent directory
echo "[+] Creating agent directory..."
mkdir -p $AGENT_DIR
cd $AGENT_DIR

# Create agent certificate
cat > agent.crt << 'EOF'
{agent_config.get('agent_cert', '')}
EOF

# Create agent key
cat > agent.key << 'EOF'
{agent_config.get('agent_key', '')}
EOF

chmod 600 agent.key

# Create agent configuration
cat > config.json << 'EOF'
{json.dumps(agent_config, indent=2)}
EOF

# Create systemd service
echo "[+] Creating systemd service..."
cat > /etc/systemd/system/dfat-agent.service << 'SEOF'
[Unit]
Description=DFAT Forensic Collection Agent
After=network.target
StartLimitInterval=0
StartLimitBurst=0

[Service]
Type=simple
User=$AGENT_USER
Group=$AGENT_USER
ExecStart=/usr/bin/python3 {agent_config.get('agent_script', '/opt/dfat-agent/agent.py')}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SEOF

# Create placeholder agent script
cat > agent.py << 'PEOF'
#!/usr/bin/env python3
import time
import json
import socket

with open('config.json', 'r') as f:
    config = json.load(f)

print(f"[+] DFAT Agent Started - ID: {{config.get('agent_id')}}")
print(f"[+] Server: {{config.get('server_url')}}")
print(f"[+] Collection interval: {{config.get('collection_interval')}}s")

while True:
    try:
        # TODO: Implement evidence collection
        # - Process enumeration
        # - Network connections
        # - File artifacts
        # - System logs
        time.sleep(config.get('collection_interval', 3600))
    except KeyboardInterrupt:
        print("[*] Agent stopped")
        break
    except Exception as e:
        print(f"[-] Error: {{str(e)}}")
        time.sleep(10)
PEOF

chmod +x agent.py

# Set proper permissions
echo "[+] Setting permissions..."
chown -R $AGENT_USER:$AGENT_USER $AGENT_DIR
chmod 700 $AGENT_DIR

# Start agent service
echo "[+] Starting DFAT Agent service..."
systemctl daemon-reload
systemctl enable dfat-agent
systemctl start dfat-agent

echo "[+] Agent deployed successfully!"
echo "[+] Agent ID: {agent_id}"
echo "[+] Status: $(systemctl is-active dfat-agent)"
"""
        return script
    
    def deploy_agent(self, target_host: str, target_port: int, ssh_user: str, 
                    ssh_password: str = None, ssh_key_path: str = None) -> Tuple[bool, str]:
        """Deploy agent to remote host via SSH"""
        agent_id = str(uuid.uuid4())
        
        try:
            # Connect via SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logger.info(f"Connecting to {target_host}:{target_port}...")
            
            if ssh_key_path:
                ssh.connect(target_host, port=target_port, username=ssh_user, 
                           key_filename=ssh_key_path, timeout=30)
                logger.info(f"SSH connected to {target_host} with key authentication")
            else:
                ssh.connect(target_host, port=target_port, username=ssh_user, 
                           password=ssh_password, timeout=30)
                logger.info(f"SSH connected to {target_host} with password authentication")
            
            # Prepare agent configuration
            agent_config = {
                'agent_id': agent_id,
                'server_url': self.config.server_url,
                'ssl_verify': self.config.get('enable_ssl', True),
                'collection_interval': 3600,
                'target_host': target_host,
                'deployment_time': datetime.now().isoformat(),
            }
            
            # Generate certificates for agent
            logger.info("Generating agent certificates...")
            cert_path, key_path = self.cert_manager.generate_agent_certificate(agent_id)
            with open(cert_path, 'r') as f:
                agent_config['agent_cert'] = f.read()
            with open(key_path, 'r') as f:
                agent_config['agent_key'] = f.read()
            
            agent_config['agent_script'] = '/opt/dfat-agent/agent.py'
            
            # Generate deployment script
            deploy_script = self.generate_agent_deployment_script(agent_id, agent_config)
            
            # Upload and execute deployment script
            logger.info("Uploading deployment script...")
            sftp = ssh.open_sftp()
            remote_script = f"/tmp/dfat_deploy_{agent_id}.sh"
            
            with sftp.file(remote_script, 'w') as f:
                f.write(deploy_script)
            
            # Make script executable
            ssh.exec_command(f"chmod +x {remote_script}")
            
            # Execute deployment
            logger.info("Executing deployment script...")
            stdin, stdout, stderr = ssh.exec_command(f"bash {remote_script}")
            
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            logger.debug(f"Deployment output:\\n{output}")
            
            # Cleanup remote script
            ssh.exec_command(f"rm -f {remote_script}")
            
            sftp.close()
            ssh.close()
            
            if exit_code == 0:
                # Create agent record
                try:
                    ip_address = socket.gethostbyname(target_host)
                except:
                    ip_address = target_host
                
                agent = RemoteAgent(
                    agent_id=agent_id,
                    hostname=target_host,
                    ip_address=ip_address,
                    port=target_port,
                    os_type="linux",
                    os_version="unknown",
                    status=AgentStatus.ONLINE,
                    first_deployed=datetime.now(),
                    last_seen=datetime.now(),
                    ssh_user=ssh_user,
                    ssh_port=target_port,
                )
                
                self.agents[agent_id] = agent
                logger.info(f"Agent deployed successfully: {agent_id}")
                return True, agent_id
            else:
                error_msg = f"Deployment failed with exit code {exit_code}: {error}"
                logger.error(error_msg)
                return False, error_msg
        
        except Exception as e:
            error_msg = f"Agent deployment error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
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
            
            # Stop and remove systemd service
            cleanup_command = """
            systemctl stop dfat-agent || true
            systemctl disable dfat-agent || true
            rm -rf /opt/dfat-agent
            rm -f /etc/systemd/system/dfat-agent.service
            systemctl daemon-reload
            echo "Agent cleanup complete"
            """
            
            logger.info(f"Removing agent {agent_id}...")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(agent.hostname, port=agent.ssh_port, username=agent.ssh_user, timeout=30)
            
            stdin, stdout, stderr = ssh.exec_command(cleanup_command)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8')
            
            ssh.close()
            
            if exit_code == 0:
                del self.agents[agent_id]
                logger.info(f"Agent removed successfully: {agent_id}")
                return True, "Agent removed successfully"
            else:
                error = stderr.read().decode('utf-8')
                logger.error(f"Error removing agent: {error}")
                return False, error
        
        except Exception as e:
            error_msg = f"Error removing agent: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
