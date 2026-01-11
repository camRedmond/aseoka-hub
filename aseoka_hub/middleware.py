"""Hub authentication middleware for ASEOKA."""

from typing import TYPE_CHECKING, ClassVar

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from aseoka_hub.logging import get_logger
from aseoka_hub.auth import (
    AuthInfo,
    TokenManager,
    extract_api_key,
    extract_bearer_token,
    verify_api_key_with_bcrypt,
    verify_mtls_headers,
)

if TYPE_CHECKING:
    from aseoka_hub.database import HubDatabase

logger = get_logger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """Authenticate all requests with multiple methods.

    Authentication methods (tried in order):
    1. mTLS headers (from nginx)
    2. API key (X-API-Key header or Authorization: Bearer ask_xxx)
    3. JWT token (Authorization: Bearer <jwt>)
    """

    # Paths that don't require authentication
    EXEMPT_PATHS: ClassVar[set[str]] = {
        "/",
        "/health",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/install.sh",
        "/bootstrap",
        "/auth/login",
    }

    # WebSocket paths handle their own auth
    WEBSOCKET_PATHS: ClassVar[set[str]] = {
        "/ws/dashboard",
        "/ws/agent/",
    }

    async def dispatch(self, request: Request, call_next):
        """Process request through authentication.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response
        """
        path = request.url.path

        # Allow exempt paths
        if path in self.EXEMPT_PATHS or path.rstrip("/") in self.EXEMPT_PATHS:
            return await call_next(request)

        # WebSockets handle their own auth
        for ws_path in self.WEBSOCKET_PATHS:
            if path.startswith(ws_path):
                return await call_next(request)

        # Get settings and database from app state
        settings = getattr(request.app.state, "settings", None)
        database = getattr(request.app.state, "database", None)

        # Check if auth is required
        require_auth = True
        if settings:
            require_auth = getattr(settings, "hub_require_auth", True)

        if not require_auth:
            # Auth optional - still try to extract for context
            if database:
                auth_info = await self._try_authenticate(request, database, settings)
                if auth_info:
                    request.state.auth = auth_info
            return await call_next(request)

        # Auth is required
        if not database:
            return JSONResponse(
                status_code=503,
                content={"detail": "Authentication service unavailable"},
            )

        auth_info = await self._try_authenticate(request, database, settings)

        if not auth_info:
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"},
                headers={"WWW-Authenticate": "Bearer, ApiKey"},
            )

        request.state.auth = auth_info
        return await call_next(request)

    async def _try_authenticate(
        self,
        request: Request,
        database: "HubDatabase",
        settings,
    ) -> AuthInfo | None:
        """Try all authentication methods in order.

        Args:
            request: Incoming request
            database: Database instance
            settings: App settings

        Returns:
            AuthInfo if authenticated, None otherwise
        """
        headers = dict(request.headers)

        # 1. Try mTLS (nginx headers)
        mtls_enabled = getattr(settings, "hub_mtls_enabled", False) if settings else False
        if mtls_enabled:
            agent_id_header = headers.get("x-agent-id")
            cert_valid_header = headers.get("x-client-cert-valid")

            if agent_id_header or cert_valid_header:
                auth_info = await verify_mtls_headers(
                    agent_id_header,
                    cert_valid_header,
                    database,
                )
                if auth_info:
                    logger.debug("auth_mtls_success", agent_id=auth_info.agent_id)
                    return auth_info

        # 2. Try API key
        api_key_enabled = getattr(settings, "hub_api_key_enabled", True) if settings else True
        if api_key_enabled:
            api_key = extract_api_key(headers)
            if api_key:
                auth_info = await verify_api_key_with_bcrypt(api_key, database)
                if auth_info:
                    logger.debug("auth_api_key_success", agent_id=auth_info.agent_id)
                    return auth_info

        # 3. Try JWT token
        auth_header = headers.get("authorization")
        token = extract_bearer_token(auth_header)

        if token and not token.startswith("ask_"):
            # It's a JWT token, not an API key
            jwt_secret = None
            jwt_expiry = 60

            if settings:
                jwt_secret = getattr(settings, "hub_jwt_secret", None)
                jwt_expiry = getattr(settings, "hub_jwt_expiry_minutes", 60)

            if jwt_secret:
                token_manager = TokenManager(
                    secret=jwt_secret,
                    expiry_minutes=jwt_expiry,
                )
                auth_info = token_manager.verify_token(token)
                if auth_info:
                    logger.debug("auth_jwt_success", agent_id=auth_info.agent_id)
                    return auth_info

        return None


def get_auth_info(request: Request) -> AuthInfo | None:
    """Get authentication info from request state.

    Args:
        request: Request object

    Returns:
        AuthInfo or None
    """
    return getattr(request.state, "auth", None)


def require_auth(request: Request) -> AuthInfo:
    """Get authentication info or raise 401.

    Args:
        request: Request object

    Returns:
        AuthInfo

    Raises:
        HTTPException: If not authenticated
    """
    auth_info = get_auth_info(request)
    if not auth_info:
        raise HTTPException(status_code=401, detail="Authentication required")
    return auth_info


def require_agent_match(request: Request, agent_id: str) -> AuthInfo:
    """Verify authenticated agent matches the path agent_id.

    Args:
        request: Request object
        agent_id: Agent ID from path

    Returns:
        AuthInfo

    Raises:
        HTTPException: If not authenticated or agent mismatch
    """
    auth_info = require_auth(request)

    # Admin can access any agent
    if auth_info.is_admin:
        return auth_info

    # Agent can only access their own resources
    if auth_info.agent_id and auth_info.agent_id != agent_id:
        raise HTTPException(
            status_code=403,
            detail="Access denied: Agent ID mismatch",
        )

    return auth_info


def require_admin(request: Request) -> AuthInfo:
    """Require admin permissions.

    Args:
        request: Request object

    Returns:
        AuthInfo

    Raises:
        HTTPException: If not admin
    """
    auth_info = require_auth(request)

    if not auth_info.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    return auth_info


def require_permission(request: Request, permission: str) -> AuthInfo:
    """Require a specific permission.

    Args:
        request: Request object
        permission: Required permission

    Returns:
        AuthInfo

    Raises:
        HTTPException: If permission not granted
    """
    auth_info = require_auth(request)

    if not auth_info.has_permission(permission):
        raise HTTPException(
            status_code=403,
            detail=f"Permission denied: {permission} required",
        )

    return auth_info
