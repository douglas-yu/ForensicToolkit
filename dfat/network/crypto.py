"""
TLS certificate management and encryption
"""

import os
import ssl
from pathlib import Path
from datetime import datetime
import datetime as dt

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from dfat.utils.logger import setup_logger

logger = setup_logger(__name__)


class CertificateManager:
    """Manages TLS certificates for secure communication"""
    
    def __init__(self, cert_dir: Path):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
        self.server_cert = self.cert_dir / 'server.crt'
        self.server_key = self.cert_dir / 'server.key'
        
        if CRYPTOGRAPHY_AVAILABLE:
            if not self.server_cert.exists() or not self.server_key.exists():
                self.generate_server_certificate()
    
    def generate_server_certificate(self):
        """Generate self-signed server certificate"""
        if not CRYPTOGRAPHY_AVAILABLE:
            logger.warning("Cryptography library not installed. Skipping certificate generation.")
            return
        
        logger.info("Generating server certificate...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DFAT"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"dfat.local"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + dt.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.DNSName(u"127.0.0.1"),
                x509.DNSName(u"dfat.local"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Write certificate
        with open(self.server_cert, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Write private key
        with open(self.server_key, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        os.chmod(self.server_key, 0o600)
        logger.info(f"Server certificate generated: {self.server_cert}")
    
    def generate_agent_certificate(self, agent_id: str) -> tuple:
        """Generate certificate for remote agent"""
        if not CRYPTOGRAPHY_AVAILABLE:
            return None, None
        
        agent_cert = self.cert_dir / f'agent_{agent_id}.crt'
        agent_key = self.cert_dir / f'agent_{agent_id}.key'
        
        if agent_cert.exists() and agent_key.exists():
            return agent_cert, agent_key
        
        logger.info(f"Generating agent certificate for: {agent_id}")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"agent-{agent_id}"),
        ])
        
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"dfat"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + dt.timedelta(days=90)
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Write certificate and key
        with open(agent_cert, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(agent_key, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        os.chmod(agent_key, 0o600)
        return agent_cert, agent_key
    
    def get_ssl_context(self, is_server=True):
        """Get configured SSL context"""
        context = ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH if is_server else ssl.Purpose.SERVER_AUTH
        )
        
        if is_server and self.server_cert.exists() and self.server_key.exists():
            context.load_cert_chain(str(self.server_cert), str(self.server_key))
        
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context
