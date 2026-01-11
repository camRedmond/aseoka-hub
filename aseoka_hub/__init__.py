"""ASEOKA Hub Server.

Central coordination server for ASEOKA agents.
Runs on your VPS at hub.aseoka.com
"""

from aseoka_hub.auth import (
    AuthInfo,
    TokenManager,
    generate_api_key,
    generate_provisioning_token,
    hash_provisioning_token,
)
from aseoka_hub.crypto import (
    CertificateAuthority,
    generate_agent_cert,
    generate_ca,
    generate_server_cert,
)
from aseoka_hub.database import (
    Activity,
    Agent,
    APIKey,
    Certificate,
    Client,
    HubDatabase,
    ProvisioningToken,
)
from aseoka_hub.middleware import (
    AuthMiddleware,
    get_auth_info,
    require_admin,
    require_agent_match,
    require_auth,
    require_permission,
)
from aseoka_hub.playbook import (
    CodeExample,
    PlaybookEntry,
    PlaybookManager,
    PlaybookOutcome,
)
from aseoka_hub.server import app, create_app

__version__ = "1.0.0"

__all__ = [
    # Database models
    "Activity",
    "Agent",
    "APIKey",
    "Certificate",
    "Client",
    "HubDatabase",
    "ProvisioningToken",
    # Authentication
    "AuthInfo",
    "AuthMiddleware",
    "TokenManager",
    "generate_api_key",
    "generate_provisioning_token",
    "get_auth_info",
    "hash_provisioning_token",
    "require_admin",
    "require_agent_match",
    "require_auth",
    "require_permission",
    # Cryptography
    "CertificateAuthority",
    "generate_agent_cert",
    "generate_ca",
    "generate_server_cert",
    # Playbook
    "CodeExample",
    "PlaybookEntry",
    "PlaybookManager",
    "PlaybookOutcome",
    # Server
    "app",
    "create_app",
]
