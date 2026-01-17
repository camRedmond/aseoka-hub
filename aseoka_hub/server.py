"""Hub server for ASEOKA."""

import asyncio
import ipaddress
import json
import os as _os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from pydantic.functional_validators import AfterValidator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from typing_extensions import Annotated

from aseoka_hub.logging import get_logger
from aseoka_hub.types import generate_id
from aseoka_hub.auth import AuthInfo, TokenManager
from aseoka_hub.database import HubDatabase, Agent, Client, Activity, Alert, User
from aseoka_hub.health_monitor import HealthMonitor
from aseoka_hub.middleware import AuthMiddleware, get_auth_info
from aseoka_hub.playbook import PlaybookManager, PlaybookEntry, PlaybookOutcome, CodeExample

logger = get_logger(__name__)

# =============================================================================
# Security: Rate Limiting
# =============================================================================

# Rate limiter setup - uses client IP as key
limiter = Limiter(key_func=get_remote_address)

# Rate limit configurations (can be overridden via environment)
RATE_LIMIT_LOGIN = _os.environ.get("ASEOKA_RATE_LIMIT_LOGIN", "5/minute")
RATE_LIMIT_BOOTSTRAP = _os.environ.get("ASEOKA_RATE_LIMIT_BOOTSTRAP", "10/minute")
RATE_LIMIT_DEFAULT = _os.environ.get("ASEOKA_RATE_LIMIT_DEFAULT", "60/minute")


# =============================================================================
# Security: SSRF Protection
# =============================================================================

# Private IP ranges that should be blocked in callback URLs
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
]


def validate_callback_url(url: str | None) -> str | None:
    """Validate callback URL to prevent SSRF attacks.

    Args:
        url: The callback URL to validate

    Returns:
        The validated URL if safe, None if empty

    Raises:
        ValueError: If URL is unsafe (private IP, invalid scheme, etc.)
    """
    if not url:
        return None

    # Enforce length limit
    if len(url) > 2048:
        raise ValueError("Callback URL too long (max 2048 characters)")

    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError("Invalid callback URL format")

    # Validate scheme
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Callback URL must use http or https scheme")

    # Validate hostname exists
    if not parsed.hostname:
        raise ValueError("Callback URL must have a hostname")

    # Check for private/internal IPs
    try:
        # Try to resolve as IP address
        ip = ipaddress.ip_address(parsed.hostname)
        for network in PRIVATE_IP_RANGES:
            if ip in network:
                raise ValueError(f"Callback URL cannot point to private IP range: {network}")
    except ValueError as e:
        if "private IP" in str(e):
            raise
        # Not an IP address, it's a hostname - check for localhost variants
        hostname_lower = parsed.hostname.lower()
        if hostname_lower in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            raise ValueError("Callback URL cannot point to localhost")
        # Block common cloud metadata hostnames
        if hostname_lower in ("metadata.google.internal", "metadata", "169.254.169.254"):
            raise ValueError("Callback URL cannot point to cloud metadata service")

    return url


# =============================================================================
# Security: WebSocket Connection Limits
# =============================================================================

# Maximum WebSocket connections
MAX_AGENT_CONNECTIONS = int(_os.environ.get("ASEOKA_MAX_AGENT_CONNECTIONS", "1000"))
MAX_DASHBOARD_CONNECTIONS = int(_os.environ.get("ASEOKA_MAX_DASHBOARD_CONNECTIONS", "100"))
MAX_CONNECTIONS_PER_CLIENT = int(_os.environ.get("ASEOKA_MAX_CONNECTIONS_PER_CLIENT", "50"))


# WebSocket connection tracking
_connected_agents: dict[str, WebSocket] = {}
# Dashboard subscribers now track client_id for multi-tenant filtering
# Format: {websocket: {"client_id": str | None, "is_admin": bool}}
_dashboard_subscribers: dict[WebSocket, dict[str, Any]] = {}
_agent_last_seen: dict[str, datetime] = {}

# Cache of agent_id -> client_id for efficient broadcast filtering
_agent_client_map: dict[str, str] = {}

# Per-client connection counters for limiting
_client_connection_counts: dict[str, int] = {}


# Request/Response models

class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    timestamp: str
    version: str = "4.0.0"


class RegisterAgentRequest(BaseModel):
    """Agent registration request."""

    client_id: str = Field(..., max_length=100)
    site_url: str = Field(..., max_length=2048)
    site_name: str = Field(..., max_length=200)
    platform: str | None = Field(default=None, max_length=100)
    callback_url: str | None = Field(default=None, max_length=2048)
    has_repo_access: bool = False
    has_github_access: bool = False
    llm_provider: str = Field(default="mock", max_length=50)

    @field_validator("callback_url")
    @classmethod
    def validate_callback(cls, v: str | None) -> str | None:
        """Validate callback URL to prevent SSRF attacks."""
        return validate_callback_url(v)


class RegisterAgentResponse(BaseModel):
    """Agent registration response."""

    agent_id: str
    client_id: str
    site_url: str
    registered_at: str


class HeartbeatRequest(BaseModel):
    """Agent heartbeat request."""

    agent_id: str = Field(..., max_length=100)
    health_score: int = Field(default=0, ge=0, le=100)
    active_issues: int = Field(default=0, ge=0, le=100000)
    pending_fixes: int = Field(default=0, ge=0, le=100000)


class HeartbeatResponse(BaseModel):
    """Agent heartbeat response."""

    acknowledged: bool
    server_time: str


class AgentResponse(BaseModel):
    """Agent details response."""

    agent_id: str
    client_id: str
    site_url: str
    site_name: str
    platform: str | None
    tier: str
    status: str
    health_score: int
    active_issues: int = 0
    pending_fixes: int = 0
    last_heartbeat: str | None
    registered_at: str | None
    has_repo_access: bool
    has_github_access: bool


class ClientResponse(BaseModel):
    """Client details response."""

    client_id: str
    client_name: str
    tier: str
    max_agents: int
    max_pages_per_scan: int
    max_fixes_per_month: int
    current_month_fixes: int


class CreateClientRequest(BaseModel):
    """Create client request."""

    client_name: str = Field(..., max_length=200)
    tier: str = Field(default="starter", max_length=50)
    contact_email: str | None = Field(default=None, max_length=254)
    client_id: str | None = Field(default=None, max_length=100)  # Optional custom client_id for devkit


# Playbook request/response models


class PlaybookEntryResponse(BaseModel):
    """Playbook entry response."""

    entry_id: str
    issue_type: str
    category: str
    severity: str
    title: str
    description: str = ""
    fix_description: str = ""
    fix_steps: list[str] = []
    patterns: list[str] = []
    anti_patterns: list[str] = []
    success_rate: float = 0.0
    success_count: int = 0
    failure_count: int = 0


class PlaybookQueryResponse(BaseModel):
    """Playbook query response."""

    entries: list[PlaybookEntryResponse]
    total: int


class PlaybookOutcomeRequest(BaseModel):
    """Playbook outcome request."""

    entry_id: str = Field(..., max_length=100)
    agent_id: str = Field(..., max_length=100)
    issue_id: str = Field(..., max_length=100)
    outcome: str = Field(..., pattern="^(success|failure|pending)$")
    pr_url: str | None = Field(default=None, max_length=2048)
    failure_reason: str | None = Field(default=None, max_length=1000)


class PlaybookOutcomeResponse(BaseModel):
    """Playbook outcome response."""

    outcome_id: str
    acknowledged: bool = True


class PlaybookContributeRequest(BaseModel):
    """Playbook contribution request."""

    issue_type: str = Field(..., max_length=100)
    category: str = Field(..., max_length=100)
    severity: str = Field(..., max_length=50)
    title: str = Field(..., max_length=500)
    fix_description: str = Field(..., max_length=5000)
    fix_steps: list[str] = Field(..., max_length=50)  # Max 50 steps
    contributed_by: str = Field(..., max_length=100)
    patterns: list[str] | None = Field(default=None, max_length=50)
    anti_patterns: list[str] | None = Field(default=None, max_length=50)


# WebSocket message types
class WSMessage(BaseModel):
    """WebSocket message wrapper."""

    type: str
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class WSHeartbeat(BaseModel):
    """Agent heartbeat via WebSocket."""

    health_score: int = Field(ge=0, le=100)
    active_issues: int = 0
    pending_fixes: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0


class WSActivity(BaseModel):
    """Agent activity report via WebSocket."""

    activity_type: str
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class WSStateUpdate(BaseModel):
    """Agent state change notification."""

    previous_state: str
    new_state: str
    reason: str | None = None


class WSThought(BaseModel):
    """Agent thought/reasoning for dashboard."""

    thought: str
    step: str | None = None
    confidence: float | None = None


class DashboardStats(BaseModel):
    """Dashboard statistics."""

    total_agents: int = 0
    online_agents: int = 0
    total_issues: int = 0
    pending_fixes: int = 0
    success_rate: float = 0.0


# Bootstrap models


class BootstrapRequest(BaseModel):
    """Agent bootstrap request."""

    provisioning_token: str
    site_url: str
    site_name: str
    platform: str | None = None
    hostname: str | None = None


class BootstrapResponse(BaseModel):
    """Agent bootstrap response with credentials."""

    agent_id: str
    client_id: str
    api_key: str  # Raw API key (only returned once)
    jwt_token: str  # Initial JWT token for WebSocket
    hub_url: str
    site_url: str
    certificate: str | None = None  # PEM certificate if mTLS enabled
    private_key: str | None = None  # PEM private key if mTLS enabled
    ca_cert: str | None = None  # CA certificate if mTLS enabled


class CreateProvisioningTokenRequest(BaseModel):
    """Create provisioning token request."""

    client_id: str
    tier: str = "starter"
    max_agents: int = 1
    expires_hours: int = 24


# User authentication models

class UserLoginRequest(BaseModel):
    """User login request."""

    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class UserLoginResponse(BaseModel):
    """User login response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    client_id: str
    is_admin: bool
    name: str


class UserRegisterRequest(BaseModel):
    """User registration request."""

    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=128)
    name: str = Field(..., min_length=1, max_length=200)
    client_id: str = Field(..., max_length=100)
    is_admin: bool = False


class UserResponse(BaseModel):
    """User details response."""

    user_id: str
    client_id: str
    email: str
    name: str
    is_admin: bool


class ProvisioningTokenResponse(BaseModel):
    """Provisioning token response."""

    token: str  # Raw token (only returned once)
    client_id: str
    tier: str
    max_agents: int
    expires_at: str


# Command/Diagnostics models for agent remote control

class AgentCommandRequest(BaseModel):
    """Request to execute a command on an agent."""

    command: str  # pause, resume, flush_logs, collect_diagnostics, ping
    params: dict[str, Any] = Field(default_factory=dict)


class AgentCommandResponse(BaseModel):
    """Response from agent command execution."""

    request_id: str
    command: str
    status: str  # success, error
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    timestamp: str


class SystemMetricsResponse(BaseModel):
    """System resource metrics from agent."""

    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_percent: float
    disk_used_gb: float
    disk_free_gb: float
    open_files: int
    threads: int
    is_containerized: bool = False  # True if metrics are from Docker cgroups
    timestamp: str


class AgentDiagnosticsResponse(BaseModel):
    """Full diagnostic snapshot from agent."""

    agent_id: str
    agent_version: str
    uptime_seconds: float
    python_version: str
    platform: str
    platform_version: str
    hostname: str
    config: dict[str, Any]
    current_phase: str
    is_paused: bool
    health_score: int
    system_metrics: SystemMetricsResponse
    issues_count: int
    fixes_count: int
    scans_count: int
    total_tokens_used: int
    token_usage_by_purpose: dict[str, int]
    last_scan_id: str | None = None
    last_scan_time: str | None = None
    last_heartbeat: str | None = None
    log_forwarder_stats: dict[str, int] | None = None
    timestamp: str


# Alert models

class AlertResponse(BaseModel):
    """Alert response."""

    alert_id: str
    agent_id: str
    alert_type: str
    severity: str
    title: str
    description: str
    triggered_at: str
    acknowledged_at: str | None = None
    acknowledged_by: str | None = None
    resolved_at: str | None = None
    metadata: dict[str, Any] | None = None
    # Include agent info for convenience
    agent_name: str | None = None
    agent_url: str | None = None


class AlertCountsResponse(BaseModel):
    """Alert counts by status."""

    active: int
    acknowledged: int
    resolved_24h: int


class AcknowledgeAlertRequest(BaseModel):
    """Request to acknowledge an alert."""

    acknowledged_by: str = "admin"


# WebSocket helper functions


async def broadcast_to_dashboards(
    message: dict[str, Any],
    agent_id: str | None = None,
) -> None:
    """Broadcast a message to connected dashboards with tenant filtering.

    Args:
        message: Message to broadcast
        agent_id: If provided, only broadcast to dashboards belonging to
                  the same client as this agent (admins see all)
    """
    if not _dashboard_subscribers:
        return

    # Determine which client should receive this message
    target_client_id: str | None = None
    if agent_id:
        target_client_id = _agent_client_map.get(agent_id)

    msg_str = json.dumps(message)
    disconnected: set[WebSocket] = set()

    # Send in parallel for better performance
    async def send_to_subscriber(ws: WebSocket, sub_info: dict[str, Any]) -> None:
        try:
            # Check if this subscriber should receive the message
            if target_client_id:
                sub_client_id = sub_info.get("client_id")
                is_admin = sub_info.get("is_admin", False)
                # Only send if admin or matching client
                if not is_admin and sub_client_id != target_client_id:
                    return
            await ws.send_text(msg_str)
        except Exception:
            disconnected.add(ws)

    # Use asyncio.gather for parallel sends
    await asyncio.gather(*[
        send_to_subscriber(ws, info)
        for ws, info in _dashboard_subscribers.items()
    ])

    # Clean up disconnected subscribers
    for ws in disconnected:
        _dashboard_subscribers.pop(ws, None)


async def send_to_agent(agent_id: str, message: dict[str, Any]) -> bool:
    """Send a message to a specific connected agent."""
    ws = _connected_agents.get(agent_id)
    if not ws:
        return False

    try:
        await ws.send_text(json.dumps(message))
        return True
    except Exception:
        # Agent disconnected
        _connected_agents.pop(agent_id, None)
        return False


def get_connected_agent_ids() -> list[str]:
    """Get list of currently connected agent IDs."""
    return list(_connected_agents.keys())


# Global database instance
_db: HubDatabase | None = None
_playbook: PlaybookManager | None = None
_health_monitor: HealthMonitor | None = None


def get_db() -> HubDatabase:
    """Get database instance."""
    if _db is None:
        raise RuntimeError("Database not initialized")
    return _db


def get_playbook() -> PlaybookManager:
    """Get playbook manager instance."""
    if _playbook is None:
        raise RuntimeError("Playbook manager not initialized")
    return _playbook


class HubSettings:
    """Hub server settings loaded from environment."""

    def __init__(self) -> None:
        import os

        self.hub_db_path = os.environ.get("ASEOKA_HUB_DB_PATH", "hub.db")
        self.hub_jwt_secret = os.environ.get("ASEOKA_HUB_JWT_SECRET", "")
        self.hub_jwt_expiry_minutes = int(os.environ.get("ASEOKA_HUB_JWT_EXPIRY_MINUTES", "60"))
        self.hub_api_key_enabled = os.environ.get("ASEOKA_HUB_API_KEY_ENABLED", "true").lower() == "true"
        self.hub_mtls_enabled = os.environ.get("ASEOKA_HUB_MTLS_ENABLED", "false").lower() == "true"
        self.hub_require_auth = os.environ.get("ASEOKA_HUB_REQUIRE_AUTH", "true").lower() == "true"
        self.hub_ca_dir = os.environ.get("ASEOKA_HUB_CA_DIR", ".aseoka/ca")
        # API docs disabled by default for security - enable explicitly in development
        self.hub_docs_enabled = os.environ.get("ASEOKA_HUB_DOCS_ENABLED", "false").lower() == "true"


_settings: HubSettings | None = None


def get_settings() -> HubSettings:
    """Get hub settings."""
    if _settings is None:
        raise RuntimeError("Settings not initialized")
    return _settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    import os

    global _db, _playbook, _settings
    _settings = HubSettings()
    _db = HubDatabase(_settings.hub_db_path)
    await _db.connect()

    # Store in app.state for middleware access
    app.state.settings = _settings
    app.state.database = _db

    # Initialize playbook manager with the database connection
    _playbook = PlaybookManager(_db._connection)
    await _playbook.init_schema()

    # Auto-create default devkit client if configured
    default_client_id = os.environ.get("ASEOKA_DEFAULT_CLIENT_ID")
    if default_client_id:
        existing = await _db.get_client(default_client_id)
        if not existing:
            default_client = Client(
                client_id=default_client_id,
                client_name="DevKit Client",
                tier="enterprise",
                max_agents=10,
                max_pages_per_scan=500,
                max_fixes_per_month=1000,
            )
            await _db.create_client(default_client)
            logger.info("default_client_created", client_id=default_client_id)

    # Initialize health monitor
    global _health_monitor

    async def on_alert_created(alert: Alert):
        """Broadcast new alerts to dashboards."""
        await broadcast_to_dashboards({
            "type": "alert",
            "data": {
                "alert_id": alert.alert_id,
                "agent_id": alert.agent_id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "title": alert.title,
                "description": alert.description,
                "triggered_at": alert.triggered_at.isoformat() if alert.triggered_at else None,
            },
        })

    _health_monitor = HealthMonitor(
        database=_db,
        offline_threshold_minutes=10,
        stale_threshold_minutes=5,
        low_health_threshold=50,
        critical_health_threshold=20,
        check_interval_seconds=60,
        on_alert_created=on_alert_created,
    )
    await _health_monitor.start()

    logger.info(
        "hub_server_started",
        playbook_initialized=True,
        health_monitor_enabled=True,
        auth_required=_settings.hub_require_auth,
        api_key_enabled=_settings.hub_api_key_enabled,
        mtls_enabled=_settings.hub_mtls_enabled,
    )
    yield

    # Shutdown
    if _health_monitor:
        await _health_monitor.stop()
    await _db.close()
    logger.info("hub_server_stopped")


# Create FastAPI app
# Docs are disabled by default for security - set ASEOKA_HUB_DOCS_ENABLED=true in dev
_docs_enabled = _os.environ.get("ASEOKA_HUB_DOCS_ENABLED", "false").lower() == "true"

app = FastAPI(
    title="ASEOKA Hub",
    description="Central coordination server for ASEOKA agents",
    version="4.0.0",
    lifespan=lifespan,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

# =============================================================================
# Security: Rate Limiting Setup
# =============================================================================
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# =============================================================================
# Security: CORS Configuration
# =============================================================================
# Get allowed origins from environment (comma-separated list)
_cors_origins_str = _os.environ.get("ASEOKA_HUB_CORS_ORIGINS", "http://localhost:3000,http://localhost:3002")
_cors_origins = [origin.strip() for origin in _cors_origins_str.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
)

# Add authentication middleware
app.add_middleware(AuthMiddleware)


# Health check endpoints

@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/", response_model=HealthResponse)
async def root() -> HealthResponse:
    """Root endpoint."""
    return await health_check()


# =============================================================================
# User Authentication Endpoints
# =============================================================================

@app.post("/auth/login", response_model=UserLoginResponse)
@limiter.limit(RATE_LIMIT_LOGIN)
async def user_login(request: Request, body: UserLoginRequest) -> UserLoginResponse:
    """Authenticate a user with email and password.

    Returns a JWT token for subsequent API calls.

    Security measures:
    - Rate limited to 5 requests/minute per IP
    - Account lockout after 5 failed attempts (15 minute lockout)
    - Generic error messages to prevent user enumeration
    - bcrypt password verification with constant-time comparison
    """
    import bcrypt
    import secrets

    db = get_db()
    settings = get_settings()

    # Generic error message for all auth failures (prevents user enumeration)
    auth_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
    )

    # Find user by email
    user = await db.get_user_by_email(body.email)

    if not user:
        # Perform dummy bcrypt check to prevent timing attacks
        bcrypt.checkpw(b"dummy", bcrypt.gensalt())
        raise auth_error

    # Check if account is locked
    if user.locked_until:
        if datetime.now(timezone.utc) < user.locked_until:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account temporarily locked due to too many failed attempts",
            )

    # Verify password using bcrypt
    if not bcrypt.checkpw(body.password.encode(), user.password_hash.encode()):
        # Increment failed login counter (may lock account)
        await db.increment_failed_login(user.user_id)
        logger.warning("login_failed", email=body.email, reason="invalid_password")
        raise auth_error

    # Check if user is active
    if not user.is_active:
        raise auth_error

    # Successful login - update last login and reset failed attempts
    await db.update_user_last_login(user.user_id)

    # Create JWT token
    token_manager = TokenManager(settings.hub_jwt_secret, expiry_minutes=60)
    access_token = token_manager.create_user_token(
        user_id=user.user_id,
        client_id=user.client_id,
        is_admin=user.is_admin,
    )

    logger.info("user_login_success", user_id=user.user_id, email=body.email)

    return UserLoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=3600,  # 1 hour
        user_id=user.user_id,
        client_id=user.client_id,
        is_admin=user.is_admin,
        name=user.name,
    )


@app.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMIT_LOGIN)
async def user_register(request: Request, body: UserRegisterRequest) -> UserResponse:
    """Register a new user.

    Requires admin authentication, unless this is the first user in the system.
    The first user is automatically created as an admin.
    """
    import bcrypt

    db = get_db()

    # Check if this is the first user (bootstrap case)
    user_count = await db.get_user_count()
    is_first_user = user_count == 0

    if not is_first_user:
        # Require admin auth for subsequent user creation
        auth_info = get_auth_info(request)
        if not auth_info or not auth_info.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin authentication required to register new users",
            )

    # Verify client exists
    client = await db.get_client(body.client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {body.client_id} not found",
        )

    # Check email uniqueness (case-insensitive)
    existing_user = await db.get_user_by_email(body.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Hash password with bcrypt (cost factor 12)
    password_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt(rounds=12)).decode()

    # First user is automatically an admin
    is_admin = body.is_admin or is_first_user

    # Create user
    user = User(
        user_id=generate_id("user"),
        client_id=body.client_id,
        email=body.email,
        password_hash=password_hash,
        name=body.name,
        is_admin=is_admin,
    )

    await db.create_user(user)

    logger.info(
        "user_registered",
        user_id=user.user_id,
        email=body.email,
        is_admin=is_admin,
        is_first_user=is_first_user,
    )

    return UserResponse(
        user_id=user.user_id,
        client_id=user.client_id,
        email=user.email,
        name=user.name,
        is_admin=user.is_admin,
    )


@app.get("/auth/me", response_model=UserResponse)
async def get_current_user(request: Request) -> UserResponse:
    """Get the current authenticated user's information."""
    auth_info = get_auth_info(request)

    if not auth_info or not auth_info.user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    db = get_db()
    user = await db.get_user(auth_info.user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return UserResponse(
        user_id=user.user_id,
        client_id=user.client_id,
        email=user.email,
        name=user.name,
        is_admin=user.is_admin,
    )


@app.post("/auth/validate")
async def validate_api_key(request: Request) -> dict:
    """Validate an API key and return a JWT token.

    This endpoint allows API key holders to exchange their key for a JWT token.
    Primarily used by the dashboard for initial authentication.
    """
    from aseoka_hub.auth import extract_api_key, verify_api_key_with_bcrypt

    db = get_db()
    settings = get_settings()

    # Extract API key from headers
    headers = {k.lower(): v for k, v in request.headers.items()}
    api_key = extract_api_key(headers)

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )

    # Verify API key
    auth_info = await verify_api_key_with_bcrypt(api_key, db)

    if not auth_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    # Get client_id from agent if available
    client_id = None
    if auth_info.agent_id:
        agent = await db.get_agent(auth_info.agent_id)
        if agent:
            client_id = agent.client_id

    # Create JWT token
    token_manager = TokenManager(settings.hub_jwt_secret, expiry_minutes=60)
    access_token = token_manager.create_dashboard_token(
        client_id=client_id or "admin",
        permissions=auth_info.permissions,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "agent_id": auth_info.agent_id,
        "client_id": client_id,
    }


# Client endpoints

@app.post("/clients", response_model=ClientResponse, status_code=status.HTTP_201_CREATED)
async def create_client(request: CreateClientRequest) -> ClientResponse:
    """Create a new client."""
    db = get_db()

    # Use custom client_id if provided, otherwise generate one
    client_id = request.client_id or generate_id("client")

    # Check if client already exists
    existing = await db.get_client(client_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Client {client_id} already exists",
        )

    client = Client(
        client_id=client_id,
        client_name=request.client_name,
        tier=request.tier,
        contact_email=request.contact_email,
    )

    await db.create_client(client)

    return ClientResponse(
        client_id=client.client_id,
        client_name=client.client_name,
        tier=client.tier,
        max_agents=client.max_agents,
        max_pages_per_scan=client.max_pages_per_scan,
        max_fixes_per_month=client.max_fixes_per_month,
        current_month_fixes=client.current_month_fixes,
    )


@app.get("/clients/{client_id}", response_model=ClientResponse)
async def get_client(client_id: str) -> ClientResponse:
    """Get client details."""
    db = get_db()
    client = await db.get_client(client_id)

    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {client_id} not found",
        )

    return ClientResponse(
        client_id=client.client_id,
        client_name=client.client_name,
        tier=client.tier,
        max_agents=client.max_agents,
        max_pages_per_scan=client.max_pages_per_scan,
        max_fixes_per_month=client.max_fixes_per_month,
        current_month_fixes=client.current_month_fixes,
    )


# Agent registration endpoints

@app.post("/agents/register", response_model=RegisterAgentResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMIT_BOOTSTRAP)  # Same limit as bootstrap - registration is sensitive
async def register_agent(request: Request, request_body: RegisterAgentRequest) -> RegisterAgentResponse:
    """Register a new agent or reconnect an existing one."""
    db = get_db()

    # Verify client exists
    client = await db.get_client(request_body.client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {request_body.client_id} not found",
        )

    # Check if an agent for this (client_id, site_url) already exists
    existing_agents = await db.get_agents_by_client(request_body.client_id)
    existing_agent = next(
        (a for a in existing_agents if a.site_url == request_body.site_url),
        None
    )

    if existing_agent:
        # Reconnect existing agent - update status to online and callback_url
        await db.update_agent_status(existing_agent.agent_id, "online")
        if request_body.callback_url:
            await db.update_agent_callback_url(existing_agent.agent_id, request_body.callback_url)

        logger.info(
            "agent_reconnected",
            agent_id=existing_agent.agent_id,
            client_id=request_body.client_id,
            site_url=request_body.site_url,
            callback_url=request_body.callback_url,
        )

        return RegisterAgentResponse(
            agent_id=existing_agent.agent_id,
            client_id=request_body.client_id,
            site_url=request_body.site_url,
            registered_at=existing_agent.registered_at.isoformat() if existing_agent.registered_at else datetime.now(timezone.utc).isoformat(),
        )

    # Check agent limit for new registrations
    if len(existing_agents) >= client.max_agents:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Client has reached maximum agents ({client.max_agents})",
        )

    # Create new agent
    agent_id = generate_id("agent")
    now = datetime.now(timezone.utc)

    agent = Agent(
        agent_id=agent_id,
        client_id=request_body.client_id,
        site_url=request_body.site_url,
        site_name=request_body.site_name,
        platform=request_body.platform,
        tier=client.tier,
        status="online",
        callback_url=request_body.callback_url,
        has_repo_access=request_body.has_repo_access,
        has_github_access=request_body.has_github_access,
        llm_provider=request_body.llm_provider,
    )

    await db.register_agent(agent)

    # Log activity
    await db.log_activity(
        Activity(
            activity_id=generate_id("activity"),
            agent_id=agent_id,
            activity_type="agent_registered",
            description=f"Agent registered for {request_body.site_url}",
        )
    )

    logger.info(
        "agent_registered_via_api",
        agent_id=agent_id,
        client_id=request_body.client_id,
        site_url=request_body.site_url,
    )

    return RegisterAgentResponse(
        agent_id=agent_id,
        client_id=request_body.client_id,
        site_url=request_body.site_url,
        registered_at=now.isoformat(),
    )


@app.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(request: Request, agent_id: str) -> AgentResponse:
    """Get agent details.

    Non-admin users can only access agents belonging to their client.
    """
    db = get_db()
    agent = await db.get_agent(agent_id)

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    # Check tenant isolation
    auth_info = get_auth_info(request)
    if auth_info and not auth_info.is_admin:
        if not auth_info.can_access_agent(agent.client_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: agent belongs to different client",
            )

    return AgentResponse(
        agent_id=agent.agent_id,
        client_id=agent.client_id,
        site_url=agent.site_url,
        site_name=agent.site_name,
        platform=agent.platform,
        tier=agent.tier,
        status=agent.status,
        health_score=agent.health_score,
        active_issues=agent.active_issues,
        pending_fixes=agent.pending_fixes,
        last_heartbeat=agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
        registered_at=agent.registered_at.isoformat() if agent.registered_at else None,
        has_repo_access=agent.has_repo_access,
        has_github_access=agent.has_github_access,
    )


@app.get("/agents", response_model=list[AgentResponse])
async def list_agents(
    request: Request,
    client_id: str | None = None,
    status: str | None = None,
) -> list[AgentResponse]:
    """List agents with optional filters.

    Non-admin users can only see agents belonging to their client.
    Admins can see all agents or filter by client_id.
    """
    db = get_db()
    auth_info = get_auth_info(request)

    # Determine effective client_id filter based on auth
    effective_client_id = client_id
    if auth_info:
        if not auth_info.is_admin:
            # Non-admin users can only see their own client's agents
            if not auth_info.client_id:
                # No client_id in auth - return empty list for safety
                return []
            # Override any provided client_id with the authenticated user's client_id
            effective_client_id = auth_info.client_id
        # Admins can filter by any client_id or see all

    # Fetch agents with appropriate filtering
    if effective_client_id:
        agents = await db.get_agents_by_client(effective_client_id)
        # Apply status filter if provided
        if status == "online":
            agents = [a for a in agents if a.status == "online"]
    elif status == "online":
        agents = await db.get_online_agents()
    else:
        agents = await db.get_all_agents()

    return [
        AgentResponse(
            agent_id=a.agent_id,
            client_id=a.client_id,
            site_url=a.site_url,
            site_name=a.site_name,
            platform=a.platform,
            tier=a.tier,
            status=a.status,
            health_score=a.health_score,
            active_issues=a.active_issues,
            pending_fixes=a.pending_fixes,
            last_heartbeat=a.last_heartbeat.isoformat() if a.last_heartbeat else None,
            registered_at=a.registered_at.isoformat() if a.registered_at else None,
            has_repo_access=a.has_repo_access,
            has_github_access=a.has_github_access,
        )
        for a in agents
    ]


# Heartbeat endpoints

@app.post("/agents/heartbeat", response_model=HeartbeatResponse)
@limiter.limit("120/minute")  # Higher limit for heartbeat - agents call this frequently
async def heartbeat(request: Request, request_body: HeartbeatRequest) -> HeartbeatResponse:
    """Process agent heartbeat."""
    db = get_db()

    updated = await db.update_heartbeat(
        request_body.agent_id,
        request_body.health_score,
        active_issues=request_body.active_issues,
        pending_fixes=request_body.pending_fixes,
    )

    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {request_body.agent_id} not found",
        )

    # Broadcast state update to connected dashboards
    await broadcast_to_dashboards({
        "type": "agent_state_update",
        "agent_id": request_body.agent_id,
        "data": {
            "health_score": request_body.health_score,
            "active_issues": request_body.active_issues,
            "pending_fixes": request_body.pending_fixes,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return HeartbeatResponse(
        acknowledged=True,
        server_time=datetime.now(timezone.utc).isoformat(),
    )


# Activity endpoints

@app.get("/activities")
async def list_activities(
    request: Request,
    agent_id: str | None = None,
    activity_type: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List activities with optional filters.

    Non-admin users can only see activities for their own agents.
    """
    db = get_db()
    auth_info = get_auth_info(request)

    # If agent_id provided, verify access
    if agent_id and auth_info and not auth_info.is_admin:
        agent = await db.get_agent(agent_id)
        if agent and not auth_info.can_access_agent(agent.client_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: agent belongs to different client",
            )

    activities = await db.get_activities(
        agent_id=agent_id,
        activity_type=activity_type,
        limit=min(limit, 1000),
    )

    # Filter activities by accessible agents for non-admin users
    if auth_info and not auth_info.is_admin and auth_info.client_id:
        # Get all accessible agent IDs for this client
        client_agents = await db.get_agents_by_client(auth_info.client_id)
        accessible_agent_ids = {a.agent_id for a in client_agents}
        activities = [a for a in activities if a.agent_id in accessible_agent_ids]

    return [
        {
            "activity_id": a.activity_id,
            "agent_id": a.agent_id,
            "activity_type": a.activity_type,
            "description": a.description,
            "metadata": a.metadata,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in activities
    ]


# Agent proxy endpoints - forward requests to agent's callback_url

import httpx


async def _proxy_to_agent(
    agent_id: str,
    method: str,
    path: str,
    json_body: dict | None = None,
    auth_info: AuthInfo | None = None,
) -> dict[str, Any]:
    """Proxy a request to an agent's callback_url.

    Args:
        agent_id: Agent to send request to
        method: HTTP method (GET, POST, etc.)
        path: Path to append to callback_url
        json_body: Optional JSON body for POST/PUT requests
        auth_info: Auth info for tenant validation

    Returns:
        Response from agent as dict

    Raises:
        HTTPException: If agent not found, no callback_url, or request fails
    """
    db = get_db()
    agent = await db.get_agent(agent_id)

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    # Tenant isolation check
    if auth_info and not auth_info.is_admin:
        if not auth_info.can_access_agent(agent.client_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: agent belongs to different client",
            )

    if not agent.callback_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Agent {agent_id} has no callback_url configured",
        )

    url = f"{agent.callback_url.rstrip('/')}{path}"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            if method.upper() == "GET":
                response = await client.get(url)
            elif method.upper() == "POST":
                response = await client.post(url, json=json_body or {})
            else:
                raise HTTPException(
                    status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                    detail=f"Method {method} not supported",
                )

            if response.status_code >= 400:
                error_detail = response.text
                try:
                    error_detail = response.json().get("detail", response.text)
                except Exception:
                    pass
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Agent error: {error_detail}",
                )

            return response.json()

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Request to agent {agent_id} timed out",
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to agent {agent_id}: {str(e)}",
        )


@app.get("/agents/{agent_id}/fixes")
async def get_agent_fixes(
    request: Request,
    agent_id: str,
) -> list[dict[str, Any]]:
    """Get all fixes from an agent.

    Proxies the request to the agent's /fixes endpoint.
    """
    auth_info = get_auth_info(request)
    return await _proxy_to_agent(agent_id, "GET", "/fixes", auth_info=auth_info)


@app.get("/agents/{agent_id}/fixes/{fix_id}")
async def get_agent_fix_detail(
    request: Request,
    agent_id: str,
    fix_id: str,
) -> dict[str, Any]:
    """Get detailed fix information from an agent.

    Proxies the request to the agent's /fixes/{fix_id} endpoint.
    Returns file changes, diff, confidence, and explanations.
    """
    auth_info = get_auth_info(request)
    return await _proxy_to_agent(agent_id, "GET", f"/fixes/{fix_id}", auth_info=auth_info)


class FixApprovalRequest(BaseModel):
    """Request body for fix approval."""

    comment: str | None = None


class FixRejectionRequest(BaseModel):
    """Request body for fix rejection."""

    reason: str


@app.post("/agents/{agent_id}/fixes/{fix_id}/approve")
async def approve_agent_fix(
    request: Request,
    agent_id: str,
    fix_id: str,
    body: FixApprovalRequest | None = None,
) -> dict[str, Any]:
    """Approve a fix on an agent.

    Proxies the request to the agent's /fixes/{fix_id}/approve endpoint.
    This will create a PR for the fix.
    """
    auth_info = get_auth_info(request)
    json_body = body.model_dump() if body else {}
    return await _proxy_to_agent(
        agent_id, "POST", f"/fixes/{fix_id}/approve", json_body=json_body, auth_info=auth_info
    )


@app.post("/agents/{agent_id}/fixes/{fix_id}/reject")
async def reject_agent_fix(
    request: Request,
    agent_id: str,
    fix_id: str,
    body: FixRejectionRequest,
) -> dict[str, Any]:
    """Reject a fix on an agent.

    Proxies the request to the agent's /fixes/{fix_id}/reject endpoint.
    """
    auth_info = get_auth_info(request)
    return await _proxy_to_agent(
        agent_id, "POST", f"/fixes/{fix_id}/reject", json_body=body.model_dump(), auth_info=auth_info
    )


@app.get("/agents/{agent_id}/issues")
async def get_agent_issues(
    request: Request,
    agent_id: str,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Get issues from an agent.

    Proxies the request to the agent's /issues endpoint.
    """
    auth_info = get_auth_info(request)
    path = "/issues"
    if status:
        path += f"?status={status}"
    return await _proxy_to_agent(agent_id, "GET", path, auth_info=auth_info)


# Playbook endpoints


@app.get("/playbook", response_model=PlaybookQueryResponse)
async def list_playbook_entries(
    issue_type: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    limit: int = 100,
) -> PlaybookQueryResponse:
    """Query playbook entries with optional filters.

    This endpoint returns playbook entries (solved SEO problems with solutions)
    that agents can use to generate fixes.
    """
    playbook = get_playbook()

    entries = await playbook.query_entries(
        issue_type=issue_type,
        category=category,
        severity=severity,
        limit=min(limit, 1000),
    )

    response_entries = [
        PlaybookEntryResponse(
            entry_id=e.entry_id,
            issue_type=e.issue_type,
            category=e.category,
            severity=e.severity,
            title=e.title,
            description=e.description,
            fix_description=e.fix_description,
            fix_steps=e.fix_steps,
            patterns=e.patterns,
            anti_patterns=e.anti_patterns,
            success_rate=e.success_rate,
            success_count=e.success_count,
            failure_count=e.failure_count,
        )
        for e in entries
    ]

    return PlaybookQueryResponse(
        entries=response_entries,
        total=len(response_entries),
    )


@app.get("/playbook/{entry_id}", response_model=PlaybookEntryResponse)
async def get_playbook_entry(entry_id: str) -> PlaybookEntryResponse:
    """Get a specific playbook entry by ID."""
    playbook = get_playbook()

    entry = await playbook.get_entry(entry_id)

    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook entry {entry_id} not found",
        )

    return PlaybookEntryResponse(
        entry_id=entry.entry_id,
        issue_type=entry.issue_type,
        category=entry.category,
        severity=entry.severity,
        title=entry.title,
        description=entry.description,
        fix_description=entry.fix_description,
        fix_steps=entry.fix_steps,
        patterns=entry.patterns,
        anti_patterns=entry.anti_patterns,
        success_rate=entry.success_rate,
        success_count=entry.success_count,
        failure_count=entry.failure_count,
    )


@app.post("/playbook/outcomes", response_model=PlaybookOutcomeResponse, status_code=status.HTTP_201_CREATED)
async def report_playbook_outcome(request: PlaybookOutcomeRequest) -> PlaybookOutcomeResponse:
    """Report the outcome of applying a playbook entry.

    Agents call this after a fix is merged or rejected to update
    the playbook's success/failure statistics.
    """
    playbook = get_playbook()

    # Verify the entry exists
    entry = await playbook.get_entry(request.entry_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook entry {request.entry_id} not found",
        )

    # Record the outcome
    outcome = PlaybookOutcome(
        outcome_id=generate_id("outcome"),
        entry_id=request.entry_id,
        agent_id=request.agent_id,
        issue_id=request.issue_id,
        pr_url=request.pr_url,
        outcome=request.outcome,
        failure_reason=request.failure_reason,
    )

    await playbook.record_outcome(outcome)

    logger.info(
        "playbook_outcome_recorded",
        outcome_id=outcome.outcome_id,
        entry_id=request.entry_id,
        outcome=request.outcome,
    )

    return PlaybookOutcomeResponse(
        outcome_id=outcome.outcome_id,
        acknowledged=True,
    )


@app.post("/playbook/contribute", response_model=PlaybookEntryResponse, status_code=status.HTTP_201_CREATED)
async def contribute_playbook_entry(request: PlaybookContributeRequest) -> PlaybookEntryResponse:
    """Contribute a new playbook entry.

    Agents can contribute new solutions they've discovered for SEO issues.
    """
    playbook = get_playbook()

    try:
        entry = await playbook.contribute_entry(
            issue_type=request.issue_type,
            category=request.category,
            severity=request.severity,
            title=request.title,
            fix_description=request.fix_description,
            fix_steps=request.fix_steps,
            contributed_by=request.contributed_by,
            patterns=request.patterns,
            anti_patterns=request.anti_patterns,
        )
    except Exception as e:
        # Handle unique constraint violation (duplicate issue_type + category)
        if "UNIQUE constraint" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Playbook entry for {request.issue_type}/{request.category} already exists",
            )
        raise

    logger.info(
        "playbook_entry_contributed",
        entry_id=entry.entry_id,
        issue_type=request.issue_type,
        contributed_by=request.contributed_by,
    )

    return PlaybookEntryResponse(
        entry_id=entry.entry_id,
        issue_type=entry.issue_type,
        category=entry.category,
        severity=entry.severity,
        title=entry.title,
        description=entry.description,
        fix_description=entry.fix_description,
        fix_steps=entry.fix_steps,
        patterns=entry.patterns,
        anti_patterns=entry.anti_patterns,
        success_rate=entry.success_rate,
        success_count=entry.success_count,
        failure_count=entry.failure_count,
    )


# Install/Bootstrap endpoints


INSTALL_SCRIPT_TEMPLATE = '''#!/bin/bash
# ASEOKA Agent Installation Script
# Generated automatically - do not edit

set -e

PROVISIONING_TOKEN="{token}"
HUB_URL="{hub_url}"
SITE_URL="$1"
SITE_NAME="${{2:-$SITE_URL}}"

if [ -z "$SITE_URL" ]; then
    echo "Usage: curl -sSL $HUB_URL/install.sh?token=... | bash -s -- <site_url> [site_name]"
    exit 1
fi

echo "ASEOKA Agent Installer"
echo "======================"
echo "Hub: $HUB_URL"
echo "Site: $SITE_URL"
echo ""

# Bootstrap the agent
echo "Bootstrapping agent..."
RESPONSE=$(curl -sS -X POST "$HUB_URL/bootstrap" \\
    -H "Content-Type: application/json" \\
    -d '{{"provisioning_token": "'"$PROVISIONING_TOKEN"'", "site_url": "'"$SITE_URL"'", "site_name": "'"$SITE_NAME"'"}}')

# Check for error
if echo "$RESPONSE" | grep -q '"detail"'; then
    echo "Error: $(echo "$RESPONSE" | grep -o '"detail":"[^"]*"' | cut -d'"' -f4)"
    exit 1
fi

# Extract credentials
AGENT_ID=$(echo "$RESPONSE" | grep -o '"agent_id":"[^"]*"' | cut -d'"' -f4)
API_KEY=$(echo "$RESPONSE" | grep -o '"api_key":"[^"]*"' | cut -d'"' -f4)

echo ""
echo "Agent provisioned successfully!"
echo "==============================="
echo "Agent ID: $AGENT_ID"
echo "API Key: $API_KEY"
echo ""
echo "Set these environment variables:"
echo "  export ASEOKA_HUB_URL=$HUB_URL"
echo "  export ASEOKA_AGENT_ID=$AGENT_ID"
echo "  export ASEOKA_API_KEY=$API_KEY"
echo ""
echo "Then start the agent with:"
echo "  aseoka-agent run --site-url $SITE_URL"
'''


@app.get("/install.sh")
async def get_install_script(
    token: str = Query(..., description="Provisioning token"),
) -> str:
    """Get installation script for agent provisioning.

    This endpoint returns a bash script that can be piped to bash:
    curl -sSL https://hub.aseoka.com/install.sh?token=prov_xxx | bash -s -- https://example.com
    """
    import os
    from fastapi.responses import PlainTextResponse

    # Validate token exists (but don't consume it yet)
    db = get_db()
    from aseoka_hub.auth import hash_provisioning_token

    token_hash = hash_provisioning_token(token)
    prov_token = await db.get_provisioning_token(token_hash)

    if not prov_token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid provisioning token",
        )

    # Check if token is still valid
    if prov_token.expires_at and datetime.now(timezone.utc) > prov_token.expires_at:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Provisioning token expired",
        )

    if prov_token.agents_created >= prov_token.max_agents:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Provisioning token exhausted",
        )

    # Get hub URL
    hub_url = os.environ.get("ASEOKA_HUB_URL", "http://localhost:8000")

    script = INSTALL_SCRIPT_TEMPLATE.format(
        token=token,
        hub_url=hub_url,
    )

    return PlainTextResponse(content=script, media_type="text/plain")


@app.post("/bootstrap", response_model=BootstrapResponse)
@limiter.limit(RATE_LIMIT_BOOTSTRAP)
async def bootstrap_agent(request: Request, request_body: BootstrapRequest) -> BootstrapResponse:
    """Bootstrap a new agent with credentials.

    This endpoint is called by the install script to provision a new agent.
    It validates the provisioning token, creates the agent, generates credentials,
    and optionally issues mTLS certificates.
    """
    import os

    from aseoka_hub.auth import generate_api_key, hash_provisioning_token

    db = get_db()
    settings = get_settings()

    # Validate provisioning token
    token_hash = hash_provisioning_token(request_body.provisioning_token)
    prov_token = await db.get_provisioning_token(token_hash)

    if not prov_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid provisioning token",
        )

    # Check expiration
    if prov_token.expires_at and datetime.now(timezone.utc) > prov_token.expires_at:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Provisioning token expired",
        )

    # Check agent limit
    if prov_token.agents_created >= prov_token.max_agents:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Provisioning token exhausted",
        )

    # Verify client exists
    client = await db.get_client(prov_token.client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found",
        )

    # Check client agent limit
    existing_agents = await db.get_agents_by_client(prov_token.client_id)
    if len(existing_agents) >= client.max_agents:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Client has reached maximum agents ({client.max_agents})",
        )

    # Create agent
    agent_id = generate_id("agent")

    agent = Agent(
        agent_id=agent_id,
        client_id=prov_token.client_id,
        site_url=request_body.site_url,
        site_name=request_body.site_name,
        platform=request_body.platform,
        tier=prov_token.tier,
        status="provisioned",
    )

    await db.register_agent(agent)

    # Generate API key
    raw_api_key, key_hash = generate_api_key()

    await db.create_api_key(
        agent_id=agent_id,
        key_hash=key_hash,
        name=f"Bootstrap key for {agent_id}",
        permissions=["agent"],
        created_by="bootstrap",
    )

    # Generate JWT token for WebSocket
    jwt_token = ""
    if settings.hub_jwt_secret:
        token_manager = TokenManager(
            secret=settings.hub_jwt_secret,
            expiry_minutes=settings.hub_jwt_expiry_minutes,
        )
        jwt_token = token_manager.create_token(agent_id, permissions=["agent"])

    # Generate mTLS certificate if enabled
    certificate = None
    private_key = None
    ca_cert = None

    if settings.hub_mtls_enabled:
        from aseoka_hub.crypto import CertificateAuthority

        ca = CertificateAuthority(settings.hub_ca_dir)
        if ca.is_initialized:
            import tempfile

            with tempfile.TemporaryDirectory() as tmpdir:
                from pathlib import Path

                key_path, cert_path, fingerprint = ca.issue_agent_cert(
                    agent_id=agent_id,
                    output_dir=Path(tmpdir),
                )

                private_key = key_path.read_text()
                certificate = cert_path.read_text()
                ca_cert = ca.get_ca_cert_pem().decode()

                # Register certificate in database
                await db.register_certificate(
                    agent_id=agent_id,
                    certificate_cn=f"agent-{agent_id}",
                    fingerprint=fingerprint,
                    expires_at=datetime.now(timezone.utc) + timedelta(days=365),
                )

    # Increment token usage
    await db.increment_provisioning_token_usage(token_hash)

    # Log activity
    await db.log_activity(
        Activity(
            activity_id=generate_id("activity"),
            agent_id=agent_id,
            activity_type="agent_bootstrapped",
            description=f"Agent bootstrapped for {request.site_url}",
        )
    )

    logger.info(
        "agent_bootstrapped",
        agent_id=agent_id,
        client_id=prov_token.client_id,
        site_url=request.site_url,
        mtls_enabled=certificate is not None,
    )

    hub_url = os.environ.get("ASEOKA_HUB_URL", "http://localhost:8000")

    return BootstrapResponse(
        agent_id=agent_id,
        client_id=prov_token.client_id,
        api_key=raw_api_key,
        jwt_token=jwt_token,
        hub_url=hub_url,
        site_url=request.site_url,
        certificate=certificate,
        private_key=private_key,
        ca_cert=ca_cert,
    )


# Admin response models


class AdminClientResponse(BaseModel):
    """Admin client details with agent counts."""

    client_id: str
    client_name: str
    tier: str
    contact_email: str | None
    max_agents: int
    max_pages_per_scan: int
    max_fixes_per_month: int
    current_month_fixes: int
    created_at: str | None
    # Agent counts
    total_agents: int = 0
    online_agents: int = 0
    offline_agents: int = 0


class AdminAgentResponse(BaseModel):
    """Admin agent details with full info."""

    agent_id: str
    client_id: str
    client_name: str | None = None
    site_url: str
    site_name: str
    platform: str | None
    tier: str
    status: str
    health_score: int
    active_issues: int = 0
    pending_fixes: int = 0
    last_heartbeat: str | None
    registered_at: str | None
    has_repo_access: bool
    has_github_access: bool
    llm_provider: str
    callback_url: str | None = None


class FleetHealthSummary(BaseModel):
    """Fleet-wide health summary."""

    total_clients: int
    total_agents: int
    online_agents: int
    offline_agents: int
    error_agents: int
    avg_health_score: float
    total_active_issues: int
    total_pending_fixes: int
    unhealthy_agents: int
    stale_heartbeat_agents: int
    timestamp: str


# Admin endpoints


@app.get("/admin/clients", response_model=list[AdminClientResponse])
async def admin_list_clients(
    request: Request,
    tier: str | None = None,
) -> list[AdminClientResponse]:
    """List all clients with agent counts (admin only).

    Returns all clients with their agent statistics for admin dashboard.
    """
    db = get_db()

    # Get all clients
    clients = await db.get_all_clients()

    # Get agent counts per client
    agent_counts = await db.get_client_agent_counts()

    # Filter by tier if specified
    if tier:
        clients = [c for c in clients if c.tier == tier]

    return [
        AdminClientResponse(
            client_id=c.client_id,
            client_name=c.client_name,
            tier=c.tier,
            contact_email=c.contact_email,
            max_agents=c.max_agents,
            max_pages_per_scan=c.max_pages_per_scan,
            max_fixes_per_month=c.max_fixes_per_month,
            current_month_fixes=c.current_month_fixes,
            created_at=c.created_at.isoformat() if c.created_at else None,
            total_agents=agent_counts.get(c.client_id, {}).get("total", 0),
            online_agents=agent_counts.get(c.client_id, {}).get("online", 0),
            offline_agents=agent_counts.get(c.client_id, {}).get("offline", 0),
        )
        for c in clients
    ]


class UpdateClientTierRequest(BaseModel):
    """Request to update client tier."""

    tier: Literal["starter", "pro", "enterprise"]
    max_agents: int | None = None
    max_pages_per_scan: int | None = None
    max_fixes_per_month: int | None = None


@app.put("/admin/clients/{client_id}/tier")
async def admin_update_client_tier(
    client_id: str,
    request: UpdateClientTierRequest,
) -> dict[str, Any]:
    """Update a client's tier and associated limits (admin only)."""
    db = get_db()

    # Check client exists
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {client_id} not found",
        )

    success = await db.update_client_tier(
        client_id=client_id,
        tier=request.tier,
        max_agents=request.max_agents,
        max_pages_per_scan=request.max_pages_per_scan,
        max_fixes_per_month=request.max_fixes_per_month,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update client tier",
        )

    # Get updated client data
    updated_client = await db.get_client(client_id)

    return {
        "updated": True,
        "client_id": client_id,
        "tier": updated_client.tier if updated_client else request.tier,
        "max_agents": updated_client.max_agents if updated_client else None,
        "max_pages_per_scan": updated_client.max_pages_per_scan if updated_client else None,
        "max_fixes_per_month": updated_client.max_fixes_per_month if updated_client else None,
    }


@app.get("/admin/agents", response_model=list[AdminAgentResponse])
async def admin_list_agents(
    request: Request,
    client_id: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    health_below: int | None = None,
) -> list[AdminAgentResponse]:
    """List all agents with full details (admin only).

    Returns all agents across all clients for admin dashboard.
    Supports filtering by client_id, status, and health threshold.
    """
    db = get_db()

    # Get all agents
    if client_id:
        agents = await db.get_agents_by_client(client_id)
    else:
        agents = await db.get_all_agents()

    # Apply filters
    if status_filter:
        agents = [a for a in agents if a.status == status_filter]

    if health_below is not None:
        agents = [a for a in agents if a.health_score < health_below]

    # Get client names for display
    clients = await db.get_all_clients()
    client_names = {c.client_id: c.client_name for c in clients}

    return [
        AdminAgentResponse(
            agent_id=a.agent_id,
            client_id=a.client_id,
            client_name=client_names.get(a.client_id),
            site_url=a.site_url,
            site_name=a.site_name,
            platform=a.platform,
            tier=a.tier,
            status=a.status,
            health_score=a.health_score,
            active_issues=a.active_issues,
            pending_fixes=a.pending_fixes,
            last_heartbeat=a.last_heartbeat.isoformat() if a.last_heartbeat else None,
            registered_at=a.registered_at.isoformat() if a.registered_at else None,
            has_repo_access=a.has_repo_access,
            has_github_access=a.has_github_access,
            llm_provider=a.llm_provider,
            callback_url=a.callback_url,
        )
        for a in agents
    ]


@app.get("/admin/agents/health/summary", response_model=FleetHealthSummary)
async def admin_fleet_health_summary(request: Request) -> FleetHealthSummary:
    """Get fleet-wide health summary (admin only).

    Returns aggregate metrics for the entire agent fleet.
    """
    db = get_db()
    summary = await db.get_fleet_health_summary()

    return FleetHealthSummary(
        total_clients=summary["total_clients"],
        total_agents=summary["total_agents"],
        online_agents=summary["online_agents"],
        offline_agents=summary["offline_agents"],
        error_agents=summary["error_agents"],
        avg_health_score=summary["avg_health_score"],
        total_active_issues=summary["total_active_issues"],
        total_pending_fixes=summary["total_pending_fixes"],
        unhealthy_agents=summary["unhealthy_agents"],
        stale_heartbeat_agents=summary["stale_heartbeat_agents"],
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/admin/activities", response_model=list[dict[str, Any]])
async def admin_list_activities(
    request: Request,
    agent_id: str | None = None,
    activity_type: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List all activities across all agents (admin only).

    Returns activity log for admin dashboard with optional filters.
    """
    db = get_db()

    activities = await db.get_activities(
        agent_id=agent_id,
        activity_type=activity_type,
        limit=min(limit, 1000),
    )

    return [
        {
            "activity_id": a.activity_id,
            "agent_id": a.agent_id,
            "activity_type": a.activity_type,
            "description": a.description,
            "metadata": a.metadata,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in activities
    ]


@app.get("/admin/activities/export")
async def admin_export_activities(
    format: str = Query("json", description="Export format: json or csv"),
    agent_id: str | None = None,
    activity_type: str | None = None,
    limit: int = Query(1000, ge=1, le=10000, description="Maximum activities to export"),
) -> Response:
    """Export activities as JSON or CSV (admin only).

    Returns activity log in downloadable format.
    """
    import csv
    from io import StringIO

    db = get_db()

    activities = await db.get_activities(
        agent_id=agent_id,
        activity_type=activity_type,
        limit=limit,
    )

    if format == "csv":
        # Create CSV
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["activity_id", "agent_id", "activity_type", "description", "created_at", "metadata"])
        for a in activities:
            writer.writerow([
                a.activity_id,
                a.agent_id,
                a.activity_type,
                a.description or "",
                a.created_at.isoformat() if a.created_at else "",
                str(a.metadata) if a.metadata else "",
            ])

        content = output.getvalue()
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=activities.csv"},
        )
    else:
        # Return JSON
        import json as json_module

        data = [
            {
                "activity_id": a.activity_id,
                "agent_id": a.agent_id,
                "activity_type": a.activity_type,
                "description": a.description,
                "metadata": a.metadata,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in activities
        ]
        content = json_module.dumps(data, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=activities.json"},
        )


@app.get("/admin/playbook/stats")
async def admin_playbook_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
) -> dict[str, Any]:
    """Get playbook analytics and effectiveness metrics (admin only).

    Returns activity statistics, fix rates, and agent performance data.
    """
    db = get_db()
    stats = await db.get_activity_stats(days=days)

    # Add fleet summary for context
    fleet_summary = await db.get_fleet_health_summary()

    return {
        **stats,
        "fleet_summary": {
            "total_agents": fleet_summary["total_agents"],
            "online_agents": fleet_summary["online_agents"],
            "avg_health_score": fleet_summary["avg_health_score"],
            "total_active_issues": fleet_summary["total_active_issues"],
            "total_pending_fixes": fleet_summary["total_pending_fixes"],
        },
    }


# Log ingestion and query endpoints


class LogEntryRequest(BaseModel):
    """Log entry from agent."""

    log_id: str
    level: str
    logger_name: str
    message: str
    context: dict[str, Any] | None = None
    timestamp: str | None = None


class LogIngestRequest(BaseModel):
    """Request to ingest log entries."""

    agent_id: str
    entries: list[LogEntryRequest]


class LogIngestResponse(BaseModel):
    """Response from log ingestion."""

    ingested: int
    agent_id: str


class LogEntryResponse(BaseModel):
    """Log entry in response."""

    log_id: str
    agent_id: str
    level: str
    logger_name: str
    message: str
    context: dict[str, Any] | None = None
    timestamp: str | None
    received_at: str | None


class LogStatsResponse(BaseModel):
    """Log statistics for an agent."""

    agent_id: str
    DEBUG: int = 0
    INFO: int = 0
    WARNING: int = 0
    ERROR: int = 0
    CRITICAL: int = 0
    total: int = 0


@app.post("/logs/ingest", response_model=LogIngestResponse)
async def ingest_logs(request: LogIngestRequest) -> LogIngestResponse:
    """Ingest log entries from an agent.

    Agents call this endpoint to stream their logs to the Hub for centralized monitoring.
    """
    from aseoka_hub.database import LogEntry

    db = get_db()

    # Convert request entries to LogEntry objects
    entries = [
        LogEntry(
            log_id=e.log_id,
            agent_id=request.agent_id,
            level=e.level.upper(),
            logger_name=e.logger_name,
            message=e.message,
            context=e.context,
            timestamp=datetime.fromisoformat(e.timestamp) if e.timestamp else None,
        )
        for e in request.entries
    ]

    count = await db.ingest_logs(entries)

    return LogIngestResponse(ingested=count, agent_id=request.agent_id)


@app.get("/admin/agents/{agent_id}/logs", response_model=list[LogEntryResponse])
async def admin_get_agent_logs(
    agent_id: str,
    level: str | None = None,
    logger_name: str | None = None,
    search: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[LogEntryResponse]:
    """Get logs for a specific agent (admin only).

    Supports filtering by level, logger name, search text, and time range.
    """
    db = get_db()

    # Parse datetime parameters
    since_dt = datetime.fromisoformat(since) if since else None
    until_dt = datetime.fromisoformat(until) if until else None

    logs = await db.query_logs(
        agent_id=agent_id,
        level=level,
        logger_name=logger_name,
        search=search,
        since=since_dt,
        until=until_dt,
        limit=min(limit, 1000),
        offset=offset,
    )

    return [
        LogEntryResponse(
            log_id=log.log_id,
            agent_id=log.agent_id,
            level=log.level,
            logger_name=log.logger_name,
            message=log.message,
            context=log.context,
            timestamp=log.timestamp.isoformat() if log.timestamp else None,
            received_at=log.received_at.isoformat() if log.received_at else None,
        )
        for log in logs
    ]


@app.get("/admin/agents/{agent_id}/logs/stats", response_model=LogStatsResponse)
async def admin_get_agent_log_stats(agent_id: str) -> LogStatsResponse:
    """Get log statistics for an agent (admin only).

    Returns counts of logs by level.
    """
    db = get_db()
    stats = await db.get_log_stats(agent_id)

    total = sum(stats.values())

    return LogStatsResponse(
        agent_id=agent_id,
        DEBUG=stats.get("DEBUG", 0),
        INFO=stats.get("INFO", 0),
        WARNING=stats.get("WARNING", 0),
        ERROR=stats.get("ERROR", 0),
        CRITICAL=stats.get("CRITICAL", 0),
        total=total,
    )


# Agent remote control endpoints


async def _get_agent_callback_url(agent_id: str) -> str:
    """Get agent callback URL from database.

    Args:
        agent_id: Agent ID

    Returns:
        Callback URL

    Raises:
        HTTPException: If agent not found or no callback URL
    """
    db = get_db()
    agent = await db.get_agent(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )
    if not agent.callback_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Agent {agent_id} has no callback URL configured",
        )
    return agent.callback_url


@app.post("/admin/agents/{agent_id}/command", response_model=AgentCommandResponse)
async def admin_send_agent_command(
    agent_id: str,
    request: AgentCommandRequest,
) -> AgentCommandResponse:
    """Send a command to an agent (admin only).

    Proxies the command to the agent via its callback URL.

    Available commands:
    - ping: Simple health check
    - pause: Pause scanning
    - resume: Resume scanning
    - flush_logs: Force log upload to hub
    - collect_diagnostics: Collect full diagnostics
    """
    callback_url = await _get_agent_callback_url(agent_id)
    request_id = str(uuid.uuid4())

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{callback_url}/command",
                json={
                    "command": request.command,
                    "request_id": request_id,
                    "params": request.params,
                },
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Agent returned error: {response.text}",
                )

            data = response.json()
            return AgentCommandResponse(
                request_id=data.get("request_id", request_id),
                command=data.get("command", request.command),
                status=data.get("status", "unknown"),
                data=data.get("data", {}),
                error=data.get("error"),
                timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            )

    except httpx.RequestError as e:
        logger.error("agent_command_failed", agent_id=agent_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to reach agent: {str(e)}",
        )


@app.get("/admin/agents/{agent_id}/diagnostics", response_model=AgentDiagnosticsResponse)
async def admin_get_agent_diagnostics(agent_id: str) -> AgentDiagnosticsResponse:
    """Get full diagnostics from an agent (admin only).

    Proxies the request to the agent via its callback URL.
    """
    callback_url = await _get_agent_callback_url(agent_id)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{callback_url}/diagnostics")

            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Agent returned error: {response.text}",
                )

            data = response.json()

            # Convert nested system_metrics dict to response model
            metrics_data = data.get("system_metrics", {})
            system_metrics = SystemMetricsResponse(
                cpu_percent=metrics_data.get("cpu_percent", 0),
                memory_percent=metrics_data.get("memory_percent", 0),
                memory_used_mb=metrics_data.get("memory_used_mb", 0),
                memory_available_mb=metrics_data.get("memory_available_mb", 0),
                disk_percent=metrics_data.get("disk_percent", 0),
                disk_used_gb=metrics_data.get("disk_used_gb", 0),
                disk_free_gb=metrics_data.get("disk_free_gb", 0),
                open_files=metrics_data.get("open_files", 0),
                threads=metrics_data.get("threads", 0),
                timestamp=metrics_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            )

            return AgentDiagnosticsResponse(
                agent_id=data.get("agent_id", agent_id),
                agent_version=data.get("agent_version", "unknown"),
                uptime_seconds=data.get("uptime_seconds", 0),
                python_version=data.get("python_version", "unknown"),
                platform=data.get("platform", "unknown"),
                platform_version=data.get("platform_version", "unknown"),
                hostname=data.get("hostname", "unknown"),
                config=data.get("config", {}),
                current_phase=data.get("current_phase", "unknown"),
                is_paused=data.get("is_paused", False),
                health_score=data.get("health_score", 0),
                system_metrics=system_metrics,
                issues_count=data.get("issues_count", 0),
                fixes_count=data.get("fixes_count", 0),
                scans_count=data.get("scans_count", 0),
                total_tokens_used=data.get("total_tokens_used", 0),
                token_usage_by_purpose=data.get("token_usage_by_purpose", {}),
                last_scan_id=data.get("last_scan_id"),
                last_scan_time=data.get("last_scan_time"),
                last_heartbeat=data.get("last_heartbeat"),
                log_forwarder_stats=data.get("log_forwarder_stats"),
                timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            )

    except httpx.RequestError as e:
        logger.error("agent_diagnostics_failed", agent_id=agent_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to reach agent: {str(e)}",
        )


@app.get("/admin/agents/{agent_id}/metrics")
async def admin_get_agent_metrics(agent_id: str) -> SystemMetricsResponse:
    """Get current system metrics from an agent (admin only).

    Proxies the request to the agent via its callback URL.
    """
    callback_url = await _get_agent_callback_url(agent_id)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{callback_url}/metrics")

            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Agent returned error: {response.text}",
                )

            data = response.json()

            return SystemMetricsResponse(
                cpu_percent=data.get("cpu_percent", 0),
                memory_percent=data.get("memory_percent", 0),
                memory_used_mb=data.get("memory_used_mb", 0),
                memory_available_mb=data.get("memory_available_mb", 0),
                disk_percent=data.get("disk_percent", 0),
                disk_used_gb=data.get("disk_used_gb", 0),
                disk_free_gb=data.get("disk_free_gb", 0),
                open_files=data.get("open_files", 0),
                threads=data.get("threads", 0),
                is_containerized=data.get("is_containerized", False),
                timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            )

    except httpx.RequestError as e:
        logger.error("agent_metrics_failed", agent_id=agent_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to reach agent: {str(e)}",
        )


# Alert endpoints


@app.get("/admin/alerts", response_model=list[AlertResponse])
async def admin_get_alerts(
    agent_id: str | None = Query(None, description="Filter by agent ID"),
    alert_type: str | None = Query(None, description="Filter by alert type"),
    severity: str | None = Query(None, description="Filter by severity (warning, critical)"),
    active_only: bool = Query(False, description="Only return unresolved alerts (deprecated)"),
    status: str | None = Query(None, description="Filter by status: active, acknowledged, resolved"),
    limit: int = Query(100, ge=1, le=500, description="Maximum alerts to return"),
) -> list[AlertResponse]:
    """Get alerts with optional filters (admin only)."""
    db = get_db()
    alerts = await db.get_alerts(
        agent_id=agent_id,
        alert_type=alert_type,
        severity=severity,
        active_only=active_only,
        status=status,
        limit=limit,
    )

    # Enrich with agent info
    result = []
    agents_cache: dict[str, Agent | None] = {}

    for alert in alerts:
        # Get agent info (cached)
        if alert.agent_id not in agents_cache:
            agents_cache[alert.agent_id] = await db.get_agent(alert.agent_id)

        agent = agents_cache[alert.agent_id]

        result.append(AlertResponse(
            alert_id=alert.alert_id,
            agent_id=alert.agent_id,
            alert_type=alert.alert_type,
            severity=alert.severity,
            title=alert.title,
            description=alert.description,
            triggered_at=alert.triggered_at.isoformat() if alert.triggered_at else "",
            acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            acknowledged_by=alert.acknowledged_by,
            resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None,
            metadata=alert.metadata,
            agent_name=agent.site_name if agent else None,
            agent_url=agent.site_url if agent else None,
        ))

    return result


@app.get("/admin/alerts/counts", response_model=AlertCountsResponse)
async def admin_get_alert_counts() -> AlertCountsResponse:
    """Get alert counts by status (admin only)."""
    db = get_db()
    counts = await db.get_alert_counts()

    return AlertCountsResponse(
        active=counts["active"],
        acknowledged=counts["acknowledged"],
        resolved_24h=counts["resolved_24h"],
    )


@app.get("/admin/alerts/{alert_id}", response_model=AlertResponse)
async def admin_get_alert(alert_id: str) -> AlertResponse:
    """Get a specific alert (admin only)."""
    db = get_db()
    alert = await db.get_alert(alert_id)

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    agent = await db.get_agent(alert.agent_id)

    return AlertResponse(
        alert_id=alert.alert_id,
        agent_id=alert.agent_id,
        alert_type=alert.alert_type,
        severity=alert.severity,
        title=alert.title,
        description=alert.description,
        triggered_at=alert.triggered_at.isoformat() if alert.triggered_at else "",
        acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        acknowledged_by=alert.acknowledged_by,
        resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None,
        metadata=alert.metadata,
        agent_name=agent.site_name if agent else None,
        agent_url=agent.site_url if agent else None,
    )


@app.post("/admin/alerts/{alert_id}/acknowledge")
async def admin_acknowledge_alert(
    alert_id: str,
    request: AcknowledgeAlertRequest,
) -> dict[str, Any]:
    """Acknowledge an alert (admin only)."""
    db = get_db()

    success = await db.acknowledge_alert(alert_id, request.acknowledged_by)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found or already acknowledged",
        )

    return {"acknowledged": True, "alert_id": alert_id}


@app.post("/admin/alerts/{alert_id}/resolve")
async def admin_resolve_alert(alert_id: str) -> dict[str, Any]:
    """Resolve an alert (admin only)."""
    db = get_db()

    success = await db.resolve_alert(alert_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found or already resolved",
        )

    return {"resolved": True, "alert_id": alert_id}


@app.post("/admin/provisioning-tokens", response_model=ProvisioningTokenResponse, status_code=status.HTTP_201_CREATED)
async def create_provisioning_token(request: CreateProvisioningTokenRequest) -> ProvisioningTokenResponse:
    """Create a new provisioning token (admin only).

    Provisioning tokens are used to bootstrap new agents via the install script.
    """
    from fastapi import Request as FastAPIRequest

    db = get_db()

    # Verify client exists
    client = await db.get_client(request.client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {request.client_id} not found",
        )

    # Generate token
    from aseoka_hub.auth import generate_provisioning_token

    raw_token, token_hash = generate_provisioning_token()

    expires_at = datetime.now(timezone.utc) + timedelta(hours=request.expires_hours)

    await db.create_provisioning_token(
        token_hash=token_hash,
        client_id=request.client_id,
        tier=request.tier,
        max_agents=request.max_agents,
        expires_at=expires_at,
    )

    logger.info(
        "provisioning_token_created",
        client_id=request.client_id,
        tier=request.tier,
        max_agents=request.max_agents,
    )

    return ProvisioningTokenResponse(
        token=raw_token,
        client_id=request.client_id,
        tier=request.tier,
        max_agents=request.max_agents,
        expires_at=expires_at.isoformat(),
    )


# WebSocket endpoints


@app.websocket("/ws/agent/{agent_id}")
async def agent_websocket(
    websocket: WebSocket,
    agent_id: str,
    token: str = Query(None),
) -> None:
    """WebSocket endpoint for agent connections.

    Agents connect here to send real-time updates and receive commands.
    Authentication is via JWT token passed as query parameter.
    """
    import os

    # Get JWT settings
    jwt_secret = os.environ.get("ASEOKA_JWT_SECRET")
    if not jwt_secret:
        await websocket.close(code=1008, reason="JWT not configured")
        return

    # Verify token
    if not token:
        await websocket.close(code=1008, reason="Token required")
        return

    token_manager = TokenManager(secret=jwt_secret)
    auth_info = token_manager.verify_token(token)

    if not auth_info:
        await websocket.close(code=1008, reason="Invalid token")
        return

    # Verify agent matches token
    if auth_info.agent_id != agent_id and not auth_info.is_admin:
        await websocket.close(code=1008, reason="Agent ID mismatch")
        return

    # Verify agent exists
    db = get_db()
    agent = await db.get_agent(agent_id)
    if not agent:
        await websocket.close(code=1008, reason="Agent not found")
        return

    # ==========================================================================
    # Security: Connection Limits
    # ==========================================================================
    # Check global agent connection limit
    if len(_connected_agents) >= MAX_AGENT_CONNECTIONS:
        logger.warning(
            "ws_connection_limit_reached",
            limit=MAX_AGENT_CONNECTIONS,
            agent_id=agent_id,
        )
        await websocket.close(code=1013, reason="Server at maximum capacity")
        return

    # Check per-client connection limit
    client_id = agent.client_id
    current_client_connections = _client_connection_counts.get(client_id, 0)
    if current_client_connections >= MAX_CONNECTIONS_PER_CLIENT:
        logger.warning(
            "ws_client_connection_limit_reached",
            limit=MAX_CONNECTIONS_PER_CLIENT,
            client_id=client_id,
            agent_id=agent_id,
        )
        await websocket.close(code=1013, reason="Client connection limit reached")
        return

    # Accept connection
    await websocket.accept()

    # Register connection and cache client_id for broadcast filtering
    _connected_agents[agent_id] = websocket
    _agent_last_seen[agent_id] = datetime.now(timezone.utc)

    # Increment client connection count
    _client_connection_counts[client_id] = _client_connection_counts.get(client_id, 0) + 1
    _agent_client_map[agent_id] = agent.client_id

    # Update agent status
    await db.update_agent_status(agent_id, "online")

    # Broadcast to dashboards (filtered by client_id)
    await broadcast_to_dashboards(
        {
            "type": "agent_connected",
            "data": {
                "agent_id": agent_id,
                "site_url": agent.site_url,
                "client_id": agent.client_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        },
        agent_id=agent_id,
    )

    logger.info("agent_ws_connected", agent_id=agent_id)

    json_error_count = 0
    MAX_JSON_ERRORS = 5  # Close connection after too many parse failures

    try:
        while True:
            # Receive message
            data = await websocket.receive_text()

            # Parse JSON with error handling to prevent crashes from malformed input
            try:
                msg = json.loads(data)
            except json.JSONDecodeError as e:
                json_error_count += 1
                logger.warning(
                    "ws_json_parse_error",
                    agent_id=agent_id,
                    error=str(e),
                    error_count=json_error_count,
                )
                # Send error response
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "data": {"message": "Invalid JSON format", "error": str(e)},
                }))
                # Close connection after too many errors to prevent abuse
                if json_error_count >= MAX_JSON_ERRORS:
                    await websocket.close(code=1008, reason="Too many JSON parse errors")
                    return
                continue

            msg_type = msg.get("type", "unknown")
            msg_data = msg.get("data", {})

            _agent_last_seen[agent_id] = datetime.now(timezone.utc)

            if msg_type == "heartbeat":
                # Update heartbeat in database (including active_issues and pending_fixes)
                health_score = msg_data.get("health_score", 0)
                active_issues = msg_data.get("active_issues", 0)
                pending_fixes = msg_data.get("pending_fixes", 0)
                await db.update_heartbeat(
                    agent_id,
                    health_score,
                    active_issues=active_issues,
                    pending_fixes=pending_fixes,
                )

                # Broadcast health update to connected dashboards (filtered by client)
                await broadcast_to_dashboards(
                    {
                        "type": "agent_state_update",
                        "agent_id": agent_id,
                        "data": {
                            "health_score": health_score,
                            "active_issues": active_issues,
                            "pending_fixes": pending_fixes,
                        },
                    },
                    agent_id=agent_id,
                )

                # Send acknowledgment
                await websocket.send_text(json.dumps({
                    "type": "heartbeat_ack",
                    "data": {"server_time": datetime.now(timezone.utc).isoformat()},
                }))

            elif msg_type == "activity":
                # Log activity
                activity = Activity(
                    activity_id=generate_id("activity"),
                    agent_id=agent_id,
                    activity_type=msg_data.get("activity_type", "unknown"),
                    description=msg_data.get("description", ""),
                    metadata=msg_data.get("metadata", {}),
                )
                await db.log_activity(activity)

                # Broadcast to dashboards (filtered by client)
                await broadcast_to_dashboards(
                    {
                        "type": "agent_activity",
                        "data": {
                            "agent_id": agent_id,
                            "activity": msg_data,
                        },
                    },
                    agent_id=agent_id,
                )

            elif msg_type == "state_update":
                # Broadcast state change to dashboards (filtered by client)
                await broadcast_to_dashboards(
                    {
                        "type": "agent_state_update",
                        "data": {
                            "agent_id": agent_id,
                            "previous_state": msg_data.get("previous_state"),
                            "new_state": msg_data.get("new_state"),
                            "reason": msg_data.get("reason"),
                        },
                    },
                    agent_id=agent_id,
                )

            elif msg_type == "thought":
                # Broadcast agent thought to dashboards (filtered by client)
                await broadcast_to_dashboards(
                    {
                        "type": "agent_thought",
                        "data": {
                            "agent_id": agent_id,
                            "thought": msg_data.get("thought"),
                            "step": msg_data.get("step"),
                            "confidence": msg_data.get("confidence"),
                        },
                    },
                    agent_id=agent_id,
                )

            elif msg_type == "command_response":
                # Response to a command from hub (filtered by client)
                await broadcast_to_dashboards(
                    {
                        "type": "command_response",
                        "data": {
                            "agent_id": agent_id,
                            "command_id": msg_data.get("command_id"),
                            "result": msg_data.get("result"),
                            "error": msg_data.get("error"),
                        },
                    },
                    agent_id=agent_id,
                )

            elif msg_type == "pong":
                # Response to ping, just update last seen
                pass

            else:
                logger.warning("unknown_ws_message_type", agent_id=agent_id, msg_type=msg_type)

    except WebSocketDisconnect:
        logger.info("agent_ws_disconnected", agent_id=agent_id)
    except Exception as e:
        logger.error("agent_ws_error", agent_id=agent_id, error=str(e))
    finally:
        # Get client_id before cleanup for connection count decrement
        cleanup_client_id = _agent_client_map.get(agent_id)

        # Cleanup connection (keep client_id for disconnect broadcast)
        _connected_agents.pop(agent_id, None)
        _agent_last_seen.pop(agent_id, None)

        # Decrement client connection count
        if cleanup_client_id and cleanup_client_id in _client_connection_counts:
            _client_connection_counts[cleanup_client_id] = max(
                0, _client_connection_counts[cleanup_client_id] - 1
            )

        # Update agent status
        try:
            await db.update_agent_status(agent_id, "offline")
        except Exception:
            pass

        # Broadcast to dashboards (filtered by client - uses cached client_id)
        await broadcast_to_dashboards(
            {
                "type": "agent_disconnected",
                "data": {
                    "agent_id": agent_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            },
            agent_id=agent_id,
        )

        # Now clean up the client map after broadcast
        _agent_client_map.pop(agent_id, None)


@app.websocket("/ws/dashboard")
async def dashboard_websocket(
    websocket: WebSocket,
    token: str = Query(None),
) -> None:
    """WebSocket endpoint for dashboard connections.

    Dashboards connect here to receive real-time updates about agents.
    Authentication is required via JWT token passed as query parameter.
    Agents are filtered by client_id for multi-tenant isolation.
    """
    import os

    # Get JWT settings
    jwt_secret = os.environ.get("ASEOKA_JWT_SECRET") or os.environ.get("ASEOKA_HUB_JWT_SECRET")

    # Check if auth is required (can be disabled for development)
    require_auth = os.environ.get("ASEOKA_HUB_REQUIRE_AUTH", "true").lower() == "true"

    auth_info: AuthInfo | None = None
    client_id: str | None = None
    is_admin: bool = False

    if require_auth:
        if not jwt_secret:
            await websocket.close(code=1008, reason="JWT not configured on server")
            return

        if not token:
            await websocket.close(code=1008, reason="Authentication required - token missing")
            return

        token_manager = TokenManager(secret=jwt_secret)
        auth_info = token_manager.verify_token(token)

        if not auth_info:
            await websocket.close(code=1008, reason="Invalid or expired token")
            return

        client_id = auth_info.client_id
        is_admin = auth_info.is_admin

        # Non-admin users must have a client_id
        if not is_admin and not client_id:
            await websocket.close(code=1008, reason="Token missing client_id claim")
            return

    # ==========================================================================
    # Security: Connection Limits
    # ==========================================================================
    # Check global dashboard connection limit
    if len(_dashboard_subscribers) >= MAX_DASHBOARD_CONNECTIONS:
        logger.warning(
            "dashboard_ws_connection_limit_reached",
            limit=MAX_DASHBOARD_CONNECTIONS,
            client_id=client_id,
        )
        await websocket.close(code=1013, reason="Server at maximum dashboard capacity")
        return

    # Accept connection and register with client info
    await websocket.accept()
    _dashboard_subscribers[websocket] = {
        "client_id": client_id,
        "is_admin": is_admin,
    }

    logger.info(
        "dashboard_ws_connected",
        total=len(_dashboard_subscribers),
        client_id=client_id,
        is_admin=is_admin,
    )

    try:
        # Send initial stats (filtered by client_id)
        db = get_db()
        all_agents = await db.get_all_agents()

        # Filter agents by client_id (admins see all)
        if is_admin:
            visible_agents = all_agents
        else:
            visible_agents = [a for a in all_agents if a.client_id == client_id]

        online_agents = [a for a in visible_agents if a.status == "online"]

        # Build agents array with health data for dashboard
        agents_data = [
            {
                "agent_id": a.agent_id,
                "client_id": a.client_id,
                "site_url": a.site_url,
                "site_name": a.site_name,
                "status": a.status,
                "health_score": a.health_score or 0,
                "active_issues": a.active_issues or 0,
                "pending_fixes": a.pending_fixes or 0,
            }
            for a in visible_agents
        ]

        # Filter connected_agent_ids to only those this client can see
        visible_agent_ids = {a.agent_id for a in visible_agents}
        visible_connected = [
            aid for aid in get_connected_agent_ids() if aid in visible_agent_ids
        ]

        await websocket.send_text(json.dumps({
            "type": "initial_stats",
            "data": {
                "total_agents": len(visible_agents),
                "online_agents": len(online_agents),
                "connected_agent_ids": visible_connected,
                "agents": agents_data,
                "client_id": client_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }))

        # Keep connection alive
        json_error_count = 0
        MAX_JSON_ERRORS = 5  # Close connection after too many parse failures

        while True:
            try:
                # Wait for ping/pong or client messages
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0,  # Ping every 30 seconds
                )

                # Parse JSON with error handling
                try:
                    msg = json.loads(data)
                except json.JSONDecodeError as e:
                    json_error_count += 1
                    logger.warning(
                        "dashboard_ws_json_parse_error",
                        client_id=client_id,
                        error=str(e),
                        error_count=json_error_count,
                    )
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "data": {"message": "Invalid JSON format", "error": str(e)},
                    }))
                    if json_error_count >= MAX_JSON_ERRORS:
                        await websocket.close(code=1008, reason="Too many JSON parse errors")
                        return
                    continue

                msg_type = msg.get("type")

                if msg_type == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))

                elif msg_type == "send_command":
                    # Dashboard sending command to agent
                    agent_id = msg.get("data", {}).get("agent_id")
                    command = msg.get("data", {}).get("command")
                    command_id = generate_id("cmd")

                    if agent_id and command:
                        # Verify this dashboard can access this agent
                        agent_client_id = _agent_client_map.get(agent_id)
                        can_access = is_admin or (client_id and agent_client_id == client_id)

                        if not can_access:
                            await websocket.send_text(json.dumps({
                                "type": "error",
                                "data": {
                                    "message": "Access denied: agent belongs to different client",
                                    "agent_id": agent_id,
                                },
                            }))
                            continue

                        success = await send_to_agent(agent_id, {
                            "type": "command",
                            "data": {
                                "command_id": command_id,
                                "command": command,
                                "args": msg.get("data", {}).get("args", {}),
                            },
                        })
                        await websocket.send_text(json.dumps({
                            "type": "command_sent",
                            "data": {
                                "command_id": command_id,
                                "agent_id": agent_id,
                                "success": success,
                            },
                        }))

            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                await websocket.send_text(json.dumps({"type": "ping"}))

    except WebSocketDisconnect:
        logger.info("dashboard_ws_disconnected", client_id=client_id)
    except Exception as e:
        logger.error("dashboard_ws_error", error=str(e), client_id=client_id)
    finally:
        _dashboard_subscribers.pop(websocket, None)


@app.get("/ws/stats")
async def ws_stats() -> dict[str, Any]:
    """Get WebSocket connection statistics."""
    return {
        "connected_agents": len(_connected_agents),
        "connected_agent_ids": get_connected_agent_ids(),
        "dashboard_subscribers": len(_dashboard_subscribers),
        "agent_last_seen": {
            agent_id: ts.isoformat()
            for agent_id, ts in _agent_last_seen.items()
        },
    }


def create_app(db_path: str = "hub.db") -> FastAPI:
    """Create a new FastAPI app with custom database path.

    Args:
        db_path: Path to database file

    Returns:
        FastAPI application
    """
    @asynccontextmanager
    async def custom_lifespan(app: FastAPI):
        global _db, _playbook
        _db = HubDatabase(db_path)
        await _db.connect()

        # Initialize playbook manager
        _playbook = PlaybookManager(_db._connection)
        await _playbook.init_schema()

        yield
        await _db.close()

    # Docs disabled by default for security
    docs_enabled = _os.environ.get("ASEOKA_HUB_DOCS_ENABLED", "false").lower() == "true"

    return FastAPI(
        title="ASEOKA Hub",
        description="Central coordination server for ASEOKA agents",
        version="4.0.0",
        lifespan=custom_lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )


if __name__ == "__main__":
    import os
    import uvicorn

    port = int(os.environ.get("ASEOKA_HUB_PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
