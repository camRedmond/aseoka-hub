"""Hub cryptography module for ASEOKA.

Provides X.509 certificate management for mTLS authentication.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aseoka_hub.logging import get_logger

logger = get_logger(__name__)

# Certificate validity periods (in days)
CA_VALIDITY_DAYS = 3650  # 10 years
SERVER_VALIDITY_DAYS = 365  # 1 year
AGENT_VALIDITY_DAYS = 365  # 1 year

# Key size
RSA_KEY_SIZE = 4096
RSA_PUBLIC_EXPONENT = 65537


def generate_private_key() -> rsa.RSAPrivateKey:
    """Generate a new RSA private key.

    Returns:
        RSA private key
    """
    return rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )


def serialize_private_key(key: rsa.RSAPrivateKey, password: bytes | None = None) -> bytes:
    """Serialize a private key to PEM format.

    Args:
        key: Private key to serialize
        password: Optional password for encryption

    Returns:
        PEM-encoded private key bytes
    """
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption,
    )


def serialize_certificate(cert: x509.Certificate) -> bytes:
    """Serialize a certificate to PEM format.

    Args:
        cert: Certificate to serialize

    Returns:
        PEM-encoded certificate bytes
    """
    return cert.public_bytes(serialization.Encoding.PEM)


def get_cert_fingerprint(cert: x509.Certificate) -> str:
    """Get SHA256 fingerprint of a certificate.

    Args:
        cert: Certificate

    Returns:
        Hex-encoded SHA256 fingerprint
    """
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der_bytes).hexdigest()


def generate_ca(
    common_name: str = "ASEOKA Root CA",
    organization: str = "ASEOKA",
    validity_days: int = CA_VALIDITY_DAYS,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed CA certificate.

    Args:
        common_name: CA common name
        organization: Organization name
        validity_days: Certificate validity in days

    Returns:
        Tuple of (private_key, certificate)
    """
    key = generate_private_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    return key, cert


def generate_server_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    hostname: str,
    alt_names: list[str] | None = None,
    validity_days: int = SERVER_VALIDITY_DAYS,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a server certificate signed by the CA.

    Args:
        ca_key: CA private key
        ca_cert: CA certificate
        hostname: Server hostname
        alt_names: Additional hostnames/IPs for SAN
        validity_days: Certificate validity in days

    Returns:
        Tuple of (private_key, certificate)
    """
    key = generate_private_key()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    now = datetime.now(timezone.utc)

    # Build Subject Alternative Names
    san_entries = [x509.DNSName(hostname)]
    for name in alt_names or []:
        if name.replace(".", "").isdigit():
            # IP address
            from ipaddress import ip_address
            san_entries.append(x509.IPAddress(ip_address(name)))
        else:
            san_entries.append(x509.DNSName(name))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return key, cert


def generate_agent_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    agent_id: str,
    validity_days: int = AGENT_VALIDITY_DAYS,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate an agent certificate signed by the CA.

    The agent ID is encoded as "agent-{agent_id}" in the CN field.
    This allows nginx to extract the agent ID for authentication.

    Args:
        ca_key: CA private key
        ca_cert: CA certificate
        agent_id: Agent ID
        validity_days: Certificate validity in days

    Returns:
        Tuple of (private_key, certificate)
    """
    key = generate_private_key()
    cert_cn = f"agent-{agent_id}"

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cert_cn),
    ])

    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return key, cert


def extract_agent_id_from_cert(cert: x509.Certificate) -> str | None:
    """Extract agent ID from certificate CN.

    Args:
        cert: Certificate to extract from

    Returns:
        Agent ID or None if not an agent certificate
    """
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            cn = attr.value
            if cn.startswith("agent-"):
                return cn[6:]  # Remove "agent-" prefix
    return None


class CertificateAuthority:
    """Certificate Authority for managing ASEOKA certificates."""

    def __init__(self, base_dir: str | Path):
        """Initialize certificate authority.

        Args:
            base_dir: Base directory for CA files
        """
        self.base_dir = Path(base_dir)
        self.ca_dir = self.base_dir / "ca"
        self.certs_dir = self.base_dir / "certs"

        self._ca_key: rsa.RSAPrivateKey | None = None
        self._ca_cert: x509.Certificate | None = None

    @property
    def ca_key_path(self) -> Path:
        """Path to CA private key."""
        return self.ca_dir / "ca.key"

    @property
    def ca_cert_path(self) -> Path:
        """Path to CA certificate."""
        return self.ca_dir / "ca.crt"

    @property
    def is_initialized(self) -> bool:
        """Check if CA is initialized."""
        return self.ca_cert_path.exists() and self.ca_key_path.exists()

    def initialize(
        self,
        common_name: str = "ASEOKA Root CA",
        organization: str = "ASEOKA",
        force: bool = False,
    ) -> None:
        """Initialize CA by generating root certificate.

        Args:
            common_name: CA common name
            organization: Organization name
            force: Force regeneration even if exists
        """
        if self.is_initialized and not force:
            logger.info("ca_already_initialized")
            return

        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        key, cert = generate_ca(common_name, organization)

        # Save CA key with secure permissions
        self.ca_key_path.write_bytes(serialize_private_key(key))
        self.ca_key_path.chmod(0o600)

        # Save CA certificate
        self.ca_cert_path.write_bytes(serialize_certificate(cert))

        self._ca_key = key
        self._ca_cert = cert

        logger.info("ca_initialized", path=str(self.ca_dir))

    def _ensure_loaded(self) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Ensure CA key and cert are loaded.

        Returns:
            Tuple of (ca_key, ca_cert)

        Raises:
            RuntimeError: If CA is not initialized
        """
        if self._ca_key and self._ca_cert:
            return self._ca_key, self._ca_cert

        if not self.is_initialized:
            raise RuntimeError("CA not initialized. Call initialize() first.")

        # Load CA key
        key_pem = self.ca_key_path.read_bytes()
        self._ca_key = serialization.load_pem_private_key(key_pem, password=None)

        # Load CA cert
        cert_pem = self.ca_cert_path.read_bytes()
        self._ca_cert = x509.load_pem_x509_certificate(cert_pem)

        return self._ca_key, self._ca_cert

    def get_ca_cert_pem(self) -> bytes:
        """Get CA certificate in PEM format.

        Returns:
            PEM-encoded CA certificate
        """
        _, ca_cert = self._ensure_loaded()
        return serialize_certificate(ca_cert)

    def issue_server_cert(
        self,
        hostname: str,
        alt_names: list[str] | None = None,
        output_dir: Path | None = None,
    ) -> tuple[Path, Path, str]:
        """Issue a server certificate.

        Args:
            hostname: Server hostname
            alt_names: Additional hostnames/IPs
            output_dir: Output directory (default: certs/servers/{hostname})

        Returns:
            Tuple of (key_path, cert_path, fingerprint)
        """
        ca_key, ca_cert = self._ensure_loaded()
        key, cert = generate_server_cert(ca_key, ca_cert, hostname, alt_names)
        fingerprint = get_cert_fingerprint(cert)

        if output_dir is None:
            output_dir = self.certs_dir / "servers" / hostname
        output_dir.mkdir(parents=True, exist_ok=True)

        key_path = output_dir / "server.key"
        cert_path = output_dir / "server.crt"

        # Save with secure permissions
        key_path.write_bytes(serialize_private_key(key))
        key_path.chmod(0o600)
        cert_path.write_bytes(serialize_certificate(cert))

        # Copy CA cert for convenience
        ca_copy_path = output_dir / "ca.crt"
        ca_copy_path.write_bytes(serialize_certificate(ca_cert))

        logger.info("server_cert_issued", hostname=hostname, fingerprint=fingerprint[:16])

        return key_path, cert_path, fingerprint

    def issue_agent_cert(
        self,
        agent_id: str,
        output_dir: Path | None = None,
    ) -> tuple[Path, Path, str]:
        """Issue an agent certificate.

        Args:
            agent_id: Agent ID
            output_dir: Output directory (default: certs/agents/{agent_id})

        Returns:
            Tuple of (key_path, cert_path, fingerprint)
        """
        ca_key, ca_cert = self._ensure_loaded()
        key, cert = generate_agent_cert(ca_key, ca_cert, agent_id)
        fingerprint = get_cert_fingerprint(cert)

        if output_dir is None:
            output_dir = self.certs_dir / "agents" / agent_id
        output_dir.mkdir(parents=True, exist_ok=True)

        key_path = output_dir / "agent.key"
        cert_path = output_dir / "agent.crt"

        # Save with secure permissions
        key_path.write_bytes(serialize_private_key(key))
        key_path.chmod(0o600)
        cert_path.write_bytes(serialize_certificate(cert))

        # Copy CA cert for convenience
        ca_copy_path = output_dir / "ca.crt"
        ca_copy_path.write_bytes(serialize_certificate(ca_cert))

        logger.info("agent_cert_issued", agent_id=agent_id, fingerprint=fingerprint[:16])

        return key_path, cert_path, fingerprint

    def verify_agent_cert(self, cert_pem: bytes) -> tuple[bool, str | None, str | None]:
        """Verify a certificate was issued by this CA.

        Args:
            cert_pem: PEM-encoded certificate to verify

        Returns:
            Tuple of (is_valid, agent_id, error_message)
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            _, ca_cert = self._ensure_loaded()

            # Check issuer matches
            if cert.issuer != ca_cert.subject:
                return False, None, "Certificate not issued by this CA"

            # Check validity
            now = datetime.now(timezone.utc)
            if now < cert.not_valid_before_utc.replace(tzinfo=timezone.utc):
                return False, None, "Certificate not yet valid"
            if now > cert.not_valid_after_utc.replace(tzinfo=timezone.utc):
                return False, None, "Certificate expired"

            # Extract agent ID
            agent_id = extract_agent_id_from_cert(cert)
            if not agent_id:
                return False, None, "Not an agent certificate"

            return True, agent_id, None

        except Exception as e:
            return False, None, str(e)
