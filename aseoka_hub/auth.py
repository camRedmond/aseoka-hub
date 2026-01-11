"""Hub authentication module for ASEOKA."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt

from aseoka_hub.logging import get_logger

if TYPE_CHECKING:
    from aseoka_hub.database import HubDatabase

logger = get_logger(__name__)


@dataclass
class AuthInfo:
    """Authentication information extracted from request."""

    agent_id: str | None
    key_id: str | None = None
    cert_cn: str | None = None
    auth_method: str = "none"  # api_key, mtls, jwt, none
    permissions: list[str] = field(default_factory=list)
    is_admin: bool = False

    def has_permission(self, permission: str) -> bool:
        """Check if auth has a specific permission.

        Args:
            permission: Permission to check

        Returns:
            True if permission is granted
        """
        if self.is_admin:
            return True
        return permission in self.permissions


class TokenManager:
    """JWT token management for WebSocket and API authentication."""

    def __init__(self, secret: str, expiry_minutes: int = 60):
        """Initialize token manager.

        Args:
            secret: JWT signing secret
            expiry_minutes: Token expiration time in minutes
        """
        self.secret = secret
        self.expiry_minutes = expiry_minutes

    def create_token(
        self,
        agent_id: str,
        permissions: list[str] | None = None,
        extra_claims: dict | None = None,
    ) -> str:
        """Create a JWT token for an agent.

        Args:
            agent_id: Agent ID (becomes 'sub' claim)
            permissions: List of permissions
            extra_claims: Additional claims to include

        Returns:
            Encoded JWT token
        """
        now = datetime.now(timezone.utc)
        payload = {
            "sub": agent_id,
            "iat": now,
            "exp": now + timedelta(minutes=self.expiry_minutes),
            "permissions": permissions or ["agent"],
        }

        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(payload, self.secret, algorithm="HS256")

    def verify_token(self, token: str) -> AuthInfo | None:
        """Verify a JWT token and return auth info.

        Args:
            token: JWT token to verify

        Returns:
            AuthInfo if valid, None otherwise
        """
        try:
            payload = jwt.decode(token, self.secret, algorithms=["HS256"])
            permissions = payload.get("permissions", [])

            return AuthInfo(
                agent_id=payload.get("sub"),
                auth_method="jwt",
                permissions=permissions,
                is_admin="admin" in permissions,
            )
        except jwt.ExpiredSignatureError:
            logger.warning("jwt_token_expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning("jwt_token_invalid", error=str(e))
            return None


def extract_bearer_token(authorization_header: str | None) -> str | None:
    """Extract token from Authorization: Bearer <token> header.

    Args:
        authorization_header: Authorization header value

    Returns:
        Token string or None
    """
    if not authorization_header:
        return None

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    return parts[1]


def extract_api_key(headers: dict[str, str]) -> str | None:
    """Extract API key from request headers.

    Checks:
    1. X-API-Key header
    2. Authorization: Bearer <key> (if key starts with ask_)

    Args:
        headers: Request headers dictionary

    Returns:
        API key or None
    """
    # Check X-API-Key header first
    api_key = headers.get("x-api-key")
    if api_key and api_key.startswith("ask_"):
        return api_key

    # Check Authorization header
    auth_header = headers.get("authorization")
    if auth_header:
        token = extract_bearer_token(auth_header)
        if token and token.startswith("ask_"):
            return token

    return None


async def verify_api_key_with_bcrypt(
    raw_key: str,
    database: "HubDatabase",
) -> AuthInfo | None:
    """Verify an API key using bcrypt.

    Args:
        raw_key: Raw API key (ask_xxx)
        database: Database instance

    Returns:
        AuthInfo if valid, None otherwise
    """
    try:
        import bcrypt
    except ImportError:
        logger.error("bcrypt_not_installed")
        return None

    # Get all active API keys
    all_keys = await database.get_all_api_keys()

    for key in all_keys:
        try:
            if bcrypt.checkpw(raw_key.encode(), key.key_hash.encode()):
                # Check expiration
                if key.expires_at and datetime.now(timezone.utc) > key.expires_at:
                    continue

                # Update last used
                await database.update_api_key_last_used(key.id)

                return AuthInfo(
                    agent_id=key.agent_id,
                    key_id=key.id,
                    auth_method="api_key",
                    permissions=key.permissions,
                    is_admin="admin" in key.permissions,
                )
        except Exception as e:
            logger.warning("bcrypt_check_failed", key_id=key.id, error=str(e))
            continue

    return None


async def verify_mtls_headers(
    agent_id_header: str | None,
    cert_valid_header: str | None,
    database: "HubDatabase",
) -> AuthInfo | None:
    """Verify mTLS authentication from nginx headers.

    Nginx extracts agent ID from certificate CN and passes it via headers:
    - X-Agent-ID: Agent ID extracted from CN (format: agent-{id})
    - X-Client-Cert-Valid: "SUCCESS" if certificate is valid

    Args:
        agent_id_header: X-Agent-ID header value
        cert_valid_header: X-Client-Cert-Valid header value
        database: Database instance

    Returns:
        AuthInfo if valid, None otherwise
    """
    if cert_valid_header != "SUCCESS":
        logger.debug("mtls_verification_failed", cert_valid=cert_valid_header)
        return None

    if not agent_id_header:
        logger.warning("mtls_missing_agent_id_header")
        return None

    # Agent ID is passed directly (nginx extracts from CN)
    agent_id = agent_id_header
    cert_cn = f"agent-{agent_id}"

    # Verify certificate is registered and not revoked
    cert = await database.verify_certificate(cert_cn)

    if not cert:
        logger.warning("mtls_certificate_not_registered", cn=cert_cn)
        return None

    return AuthInfo(
        agent_id=cert.agent_id,
        cert_cn=cert_cn,
        auth_method="mtls",
        permissions=["agent"],
        is_admin=False,
    )


def generate_api_key() -> tuple[str, str]:
    """Generate a new API key.

    Returns:
        Tuple of (raw_key, key_hash)
    """
    import secrets

    try:
        import bcrypt
    except ImportError:
        raise RuntimeError("bcrypt is required for API key generation")

    raw_key = f"ask_{secrets.token_urlsafe(32)}"
    key_hash = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt()).decode()

    return raw_key, key_hash


def hash_provisioning_token(raw_token: str) -> str:
    """Hash a provisioning token using SHA256.

    Args:
        raw_token: Raw provisioning token

    Returns:
        SHA256 hash of the token
    """
    import hashlib

    return hashlib.sha256(raw_token.encode()).hexdigest()


def generate_provisioning_token() -> tuple[str, str]:
    """Generate a new provisioning token.

    Returns:
        Tuple of (raw_token, token_hash)
    """
    import secrets

    raw_token = f"prov_{secrets.token_hex(32)}"
    token_hash = hash_provisioning_token(raw_token)

    return raw_token, token_hash
