"""Hub database module for ASEOKA."""

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import aiosqlite

from aseoka_hub.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Client:
    """Client organization."""

    client_id: str
    client_name: str
    tier: Literal["starter", "pro", "enterprise"] = "starter"
    contact_email: str | None = None
    max_agents: int = 1
    max_pages_per_scan: int = 50
    max_fixes_per_month: int = 10
    current_month_fixes: int = 0
    created_at: datetime | None = None


@dataclass
class Agent:
    """Registered agent."""

    agent_id: str
    client_id: str
    site_url: str
    site_name: str
    platform: str | None = None
    tier: Literal["starter", "pro", "enterprise"] = "starter"
    status: Literal["online", "offline", "error"] = "offline"
    health_score: int = 0
    active_issues: int = 0
    pending_fixes: int = 0
    last_heartbeat: datetime | None = None
    last_full_report: datetime | None = None
    registered_at: datetime | None = None
    callback_url: str | None = None
    has_repo_access: bool = False
    has_github_access: bool = False
    llm_provider: str = "mock"


@dataclass
class Activity:
    """Activity log entry."""

    activity_id: str
    agent_id: str
    activity_type: str
    description: str | None = None
    metadata: dict | None = None
    created_at: datetime | None = None


@dataclass
class APIKey:
    """API key for authentication."""

    id: str
    agent_id: str | None  # None for admin keys
    key_hash: str
    name: str
    permissions: list[str]
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked: bool = False
    created_by: str = "system"


@dataclass
class Certificate:
    """Agent certificate for mTLS."""

    id: str
    agent_id: str
    certificate_cn: str
    fingerprint: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


@dataclass
class ProvisioningToken:
    """Token for agent provisioning."""

    token_hash: str
    client_id: str
    client_name: str | None = None
    tier: str = "starter"
    hosting_type: str = "self_hosted"
    created_at: datetime | None = None
    expires_at: datetime | None = None
    max_agents: int = 1
    agents_created: int = 0
    created_by: str = "system"


@dataclass
class LogEntry:
    """Log entry from an agent."""

    log_id: str
    agent_id: str
    level: str  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    logger_name: str
    message: str
    context: dict | None = None  # Additional structured data
    timestamp: datetime | None = None
    received_at: datetime | None = None


# Hub schema SQL
HUB_SCHEMA = """
-- Clients (organizations using ASEOKA)
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    tier TEXT DEFAULT 'starter',
    contact_email TEXT,
    max_agents INTEGER DEFAULT 1,
    max_pages_per_scan INTEGER DEFAULT 50,
    max_fixes_per_month INTEGER DEFAULT 10,
    current_month_fixes INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Agents
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    client_id TEXT REFERENCES clients(client_id),
    site_url TEXT NOT NULL,
    site_name TEXT NOT NULL,
    platform TEXT,
    tier TEXT DEFAULT 'starter',
    status TEXT DEFAULT 'offline',
    health_score INTEGER DEFAULT 0,
    active_issues INTEGER DEFAULT 0,
    pending_fixes INTEGER DEFAULT 0,
    last_heartbeat TIMESTAMP,
    last_full_report TIMESTAMP,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    callback_url TEXT,
    has_repo_access BOOLEAN DEFAULT FALSE,
    has_github_access BOOLEAN DEFAULT FALSE,
    llm_provider TEXT DEFAULT 'mock'
);

-- Activities (event log)
CREATE TABLE IF NOT EXISTS activities (
    activity_id TEXT PRIMARY KEY,
    agent_id TEXT REFERENCES agents(agent_id),
    activity_type TEXT NOT NULL,
    description TEXT,
    metadata TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API Keys (bcrypt hashed)
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    agent_id TEXT,
    key_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    permissions TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    last_used_at TEXT,
    revoked INTEGER DEFAULT 0,
    created_by TEXT
);

-- Certificates for mTLS
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    certificate_cn TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER DEFAULT 0,
    revoked_at TEXT,
    revoked_reason TEXT
);

-- Provisioning tokens for agent installation
CREATE TABLE IF NOT EXISTS provisioning_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    client_name TEXT,
    tier TEXT DEFAULT 'starter',
    hosting_type TEXT DEFAULT 'self_hosted',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_agents INTEGER DEFAULT 1,
    agents_created INTEGER DEFAULT 0,
    created_by TEXT
);

-- Agent logs (streamed from agents for centralized monitoring)
CREATE TABLE IF NOT EXISTS agent_logs (
    log_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    level TEXT NOT NULL,
    logger_name TEXT NOT NULL,
    message TEXT NOT NULL,
    context TEXT,
    timestamp TEXT NOT NULL,
    received_at TEXT NOT NULL
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_agents_client ON agents(client_id);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_activities_agent ON activities(agent_id);
CREATE INDEX IF NOT EXISTS idx_activities_type ON activities(activity_type);
CREATE INDEX IF NOT EXISTS idx_api_keys_agent ON api_keys(agent_id);
CREATE INDEX IF NOT EXISTS idx_certs_agent ON certificates(agent_id);
CREATE INDEX IF NOT EXISTS idx_certs_cn ON certificates(certificate_cn);
CREATE INDEX IF NOT EXISTS idx_prov_tokens_client ON provisioning_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_logs_agent ON agent_logs(agent_id);
CREATE INDEX IF NOT EXISTS idx_logs_level ON agent_logs(level);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON agent_logs(timestamp);
"""


class HubDatabase:
    """Hub database operations."""

    def __init__(self, db_path: str | Path = "hub.db"):
        """Initialize hub database.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self._connection: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Connect to database and initialize schema."""
        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row
        await self._init_schema()
        logger.info("hub_database_connected", db_path=str(self.db_path))

    async def close(self) -> None:
        """Close database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None

    async def _init_schema(self) -> None:
        """Initialize database schema."""
        if not self._connection:
            raise RuntimeError("Database not connected")

        # Split schema into individual statements
        statements = [s.strip() for s in HUB_SCHEMA.split(";") if s.strip()]
        for statement in statements:
            await self._connection.execute(statement)
        await self._connection.commit()

    # Client operations

    async def create_client(self, client: Client) -> None:
        """Create a new client.

        Args:
            client: Client to create
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        now = datetime.now(timezone.utc).isoformat()
        await self._connection.execute(
            """INSERT INTO clients
               (client_id, client_name, tier, contact_email, max_agents,
                max_pages_per_scan, max_fixes_per_month, current_month_fixes, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                client.client_id,
                client.client_name,
                client.tier,
                client.contact_email,
                client.max_agents,
                client.max_pages_per_scan,
                client.max_fixes_per_month,
                client.current_month_fixes,
                now,
            ),
        )
        await self._connection.commit()
        logger.info("client_created", client_id=client.client_id)

    async def get_client(self, client_id: str) -> Client | None:
        """Get a client by ID.

        Args:
            client_id: Client ID

        Returns:
            Client or None if not found
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "SELECT * FROM clients WHERE client_id = ?",
            (client_id,),
        )
        row = await cursor.fetchone()

        if not row:
            return None

        return Client(
            client_id=row["client_id"],
            client_name=row["client_name"],
            tier=row["tier"],
            contact_email=row["contact_email"],
            max_agents=row["max_agents"],
            max_pages_per_scan=row["max_pages_per_scan"],
            max_fixes_per_month=row["max_fixes_per_month"],
            current_month_fixes=row["current_month_fixes"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
        )

    async def get_all_clients(self) -> list[Client]:
        """Get all clients.

        Returns:
            List of all clients
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "SELECT * FROM clients ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()

        return [
            Client(
                client_id=row["client_id"],
                client_name=row["client_name"],
                tier=row["tier"],
                contact_email=row["contact_email"],
                max_agents=row["max_agents"],
                max_pages_per_scan=row["max_pages_per_scan"],
                max_fixes_per_month=row["max_fixes_per_month"],
                current_month_fixes=row["current_month_fixes"],
                created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            )
            for row in rows
        ]

    async def get_client_agent_counts(self) -> dict[str, dict[str, int]]:
        """Get agent counts per client.

        Returns:
            Dict mapping client_id to {total, online, offline} counts
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            """SELECT client_id,
                      COUNT(*) as total,
                      SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online,
                      SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) as offline
               FROM agents
               GROUP BY client_id"""
        )
        rows = await cursor.fetchall()

        return {
            row["client_id"]: {
                "total": row["total"],
                "online": row["online"] or 0,
                "offline": row["offline"] or 0,
            }
            for row in rows
        }

    async def get_fleet_health_summary(self) -> dict[str, any]:
        """Get fleet-wide health summary for admin dashboard.

        Returns:
            Dict with fleet health metrics
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        # Get overall agent stats
        cursor = await self._connection.execute(
            """SELECT
                COUNT(*) as total_agents,
                SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online_agents,
                SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) as offline_agents,
                SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_agents,
                AVG(health_score) as avg_health_score,
                SUM(active_issues) as total_active_issues,
                SUM(pending_fixes) as total_pending_fixes
               FROM agents"""
        )
        row = await cursor.fetchone()

        # Get client count
        client_cursor = await self._connection.execute("SELECT COUNT(*) as count FROM clients")
        client_row = await client_cursor.fetchone()

        # Get agents with low health (< 50)
        unhealthy_cursor = await self._connection.execute(
            "SELECT COUNT(*) as count FROM agents WHERE health_score < 50 AND status = 'online'"
        )
        unhealthy_row = await unhealthy_cursor.fetchone()

        # Get agents with stale heartbeat (> 5 minutes)
        stale_cursor = await self._connection.execute(
            """SELECT COUNT(*) as count FROM agents
               WHERE status = 'online'
               AND datetime(last_heartbeat) < datetime('now', '-5 minutes')"""
        )
        stale_row = await stale_cursor.fetchone()

        return {
            "total_clients": client_row["count"],
            "total_agents": row["total_agents"] or 0,
            "online_agents": row["online_agents"] or 0,
            "offline_agents": row["offline_agents"] or 0,
            "error_agents": row["error_agents"] or 0,
            "avg_health_score": round(row["avg_health_score"] or 0, 1),
            "total_active_issues": row["total_active_issues"] or 0,
            "total_pending_fixes": row["total_pending_fixes"] or 0,
            "unhealthy_agents": unhealthy_row["count"] or 0,
            "stale_heartbeat_agents": stale_row["count"] or 0,
        }

    # Agent operations

    async def register_agent(self, agent: Agent) -> None:
        """Register a new agent.

        Args:
            agent: Agent to register
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        now = datetime.now(timezone.utc).isoformat()
        await self._connection.execute(
            """INSERT INTO agents
               (agent_id, client_id, site_url, site_name, platform, tier, status,
                health_score, active_issues, pending_fixes, last_heartbeat, registered_at, callback_url,
                has_repo_access, has_github_access, llm_provider)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                agent.agent_id,
                agent.client_id,
                agent.site_url,
                agent.site_name,
                agent.platform,
                agent.tier,
                agent.status,
                agent.health_score,
                agent.active_issues,
                agent.pending_fixes,
                now,
                now,
                agent.callback_url,
                agent.has_repo_access,
                agent.has_github_access,
                agent.llm_provider,
            ),
        )
        await self._connection.commit()
        logger.info("agent_registered", agent_id=agent.agent_id)

    async def get_agent(self, agent_id: str) -> Agent | None:
        """Get an agent by ID.

        Args:
            agent_id: Agent ID

        Returns:
            Agent or None if not found
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "SELECT * FROM agents WHERE agent_id = ?",
            (agent_id,),
        )
        row = await cursor.fetchone()

        if not row:
            return None

        return self._row_to_agent(row)

    async def get_agents_by_client(self, client_id: str) -> list[Agent]:
        """Get all agents for a client.

        Args:
            client_id: Client ID

        Returns:
            List of agents
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "SELECT * FROM agents WHERE client_id = ?",
            (client_id,),
        )
        rows = await cursor.fetchall()

        return [self._row_to_agent(row) for row in rows]

    async def update_heartbeat(
        self,
        agent_id: str,
        health_score: int = 0,
        active_issues: int | None = None,
        pending_fixes: int | None = None,
    ) -> bool:
        """Update agent heartbeat.

        Args:
            agent_id: Agent ID
            health_score: Current health score
            active_issues: Number of active issues (optional)
            pending_fixes: Number of pending fixes (optional)

        Returns:
            True if agent exists and was updated
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        now = datetime.now(timezone.utc).isoformat()

        # Build the update query dynamically based on provided values
        if active_issues is not None and pending_fixes is not None:
            cursor = await self._connection.execute(
                """UPDATE agents
                   SET last_heartbeat = ?, status = 'online', health_score = ?,
                       active_issues = ?, pending_fixes = ?
                   WHERE agent_id = ?""",
                (now, health_score, active_issues, pending_fixes, agent_id),
            )
        else:
            cursor = await self._connection.execute(
                """UPDATE agents
                   SET last_heartbeat = ?, status = 'online', health_score = ?
                   WHERE agent_id = ?""",
                (now, health_score, agent_id),
            )
        await self._connection.commit()

        updated = cursor.rowcount > 0
        if updated:
            logger.debug("heartbeat_updated", agent_id=agent_id)

        return updated

    async def update_agent_status(
        self,
        agent_id: str,
        status: Literal["online", "offline", "error"],
    ) -> bool:
        """Update agent status.

        Args:
            agent_id: Agent ID
            status: New status

        Returns:
            True if agent exists and was updated
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "UPDATE agents SET status = ? WHERE agent_id = ?",
            (status, agent_id),
        )
        await self._connection.commit()

        return cursor.rowcount > 0

    async def get_online_agents(self) -> list[Agent]:
        """Get all online agents.

        Returns:
            List of online agents
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "SELECT * FROM agents WHERE status = 'online'",
        )
        rows = await cursor.fetchall()

        return [self._row_to_agent(row) for row in rows]

    async def get_all_agents(self) -> list[Agent]:
        """Get all agents.

        Returns:
            List of all agents
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute("SELECT * FROM agents")
        rows = await cursor.fetchall()

        return [self._row_to_agent(row) for row in rows]

    def _row_to_agent(self, row: aiosqlite.Row) -> Agent:
        """Convert database row to Agent.

        Args:
            row: Database row

        Returns:
            Agent object
        """
        return Agent(
            agent_id=row["agent_id"],
            client_id=row["client_id"],
            site_url=row["site_url"],
            site_name=row["site_name"],
            platform=row["platform"],
            tier=row["tier"],
            status=row["status"],
            health_score=row["health_score"],
            active_issues=row["active_issues"] if "active_issues" in row.keys() else 0,
            pending_fixes=row["pending_fixes"] if "pending_fixes" in row.keys() else 0,
            last_heartbeat=datetime.fromisoformat(row["last_heartbeat"]) if row["last_heartbeat"] else None,
            last_full_report=datetime.fromisoformat(row["last_full_report"]) if row["last_full_report"] else None,
            registered_at=datetime.fromisoformat(row["registered_at"]) if row["registered_at"] else None,
            callback_url=row["callback_url"],
            has_repo_access=bool(row["has_repo_access"]),
            has_github_access=bool(row["has_github_access"]),
            llm_provider=row["llm_provider"],
        )

    # Activity operations

    async def log_activity(self, activity: Activity) -> None:
        """Log an activity.

        Args:
            activity: Activity to log
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        now = datetime.now(timezone.utc).isoformat()
        metadata_json = json.dumps(activity.metadata) if activity.metadata else None

        await self._connection.execute(
            """INSERT INTO activities
               (activity_id, agent_id, activity_type, description, metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                activity.activity_id,
                activity.agent_id,
                activity.activity_type,
                activity.description,
                metadata_json,
                now,
            ),
        )
        await self._connection.commit()

    async def get_activities(
        self,
        agent_id: str | None = None,
        activity_type: str | None = None,
        limit: int = 100,
    ) -> list[Activity]:
        """Get activities with optional filters.

        Args:
            agent_id: Filter by agent ID
            activity_type: Filter by activity type
            limit: Maximum number of activities to return

        Returns:
            List of activities
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        query = "SELECT * FROM activities WHERE 1=1"
        params: list = []

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        if activity_type:
            query += " AND activity_type = ?"
            params.append(activity_type)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor = await self._connection.execute(query, params)
        rows = await cursor.fetchall()

        activities = []
        for row in rows:
            metadata = json.loads(row["metadata"]) if row["metadata"] else None
            activities.append(
                Activity(
                    activity_id=row["activity_id"],
                    agent_id=row["agent_id"],
                    activity_type=row["activity_type"],
                    description=row["description"],
                    metadata=metadata,
                    created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
                )
            )

        return activities

    # API Key operations

    async def create_api_key(
        self,
        key_id: str,
        key_hash: str,
        name: str,
        agent_id: str | None = None,
        permissions: list[str] | None = None,
        expires_at: datetime | None = None,
        created_by: str = "system",
    ) -> None:
        """Create a new API key.

        Args:
            key_id: Unique key ID
            key_hash: bcrypt hash of the key
            name: Friendly name for the key
            agent_id: Agent ID (None for admin keys)
            permissions: List of permissions
            expires_at: Expiration time
            created_by: Who created the key
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        now = datetime.now(timezone.utc).isoformat()
        permissions_json = json.dumps(permissions or ["agent"])
        expires_str = expires_at.isoformat() if expires_at else None

        await self._connection.execute(
            """INSERT INTO api_keys
               (id, agent_id, key_hash, name, permissions, created_at, expires_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (key_id, agent_id, key_hash, name, permissions_json, now, expires_str, created_by),
        )
        await self._connection.commit()
        logger.info("api_key_created", key_id=key_id, agent_id=agent_id)

    async def verify_api_key(self, key_hash: str) -> APIKey | None:
        """Verify an API key by its hash.

        Note: In practice, you'd iterate over all non-revoked keys and use
        bcrypt.checkpw() since bcrypt hashes aren't directly comparable.
        This method returns the key if found by hash for testing purposes.

        Args:
            key_hash: Hash to verify

        Returns:
            APIKey if valid, None otherwise
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            """SELECT * FROM api_keys
               WHERE key_hash = ? AND revoked = 0""",
            (key_hash,),
        )
        row = await cursor.fetchone()

        if not row:
            return None

        # Check expiration
        if row["expires_at"]:
            expires = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) > expires:
                return None

        # Update last used
        now = datetime.now(timezone.utc).isoformat()
        await self._connection.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (now, row["id"]),
        )
        await self._connection.commit()

        return APIKey(
            id=row["id"],
            agent_id=row["agent_id"],
            key_hash=row["key_hash"],
            name=row["name"],
            permissions=json.loads(row["permissions"] or "[]"),
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            last_used_at=datetime.fromisoformat(row["last_used_at"]) if row["last_used_at"] else None,
            revoked=bool(row["revoked"]),
            created_by=row["created_by"] or "system",
        )

    async def get_all_api_keys(self) -> list[APIKey]:
        """Get all non-revoked API keys for bcrypt verification.

        Returns:
            List of all active API keys
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "SELECT * FROM api_keys WHERE revoked = 0"
        )
        rows = await cursor.fetchall()

        return [
            APIKey(
                id=row["id"],
                agent_id=row["agent_id"],
                key_hash=row["key_hash"],
                name=row["name"],
                permissions=json.loads(row["permissions"] or "[]"),
                created_at=datetime.fromisoformat(row["created_at"]),
                expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                last_used_at=datetime.fromisoformat(row["last_used_at"]) if row["last_used_at"] else None,
                revoked=bool(row["revoked"]),
                created_by=row["created_by"] or "system",
            )
            for row in rows
        ]

    async def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key.

        Args:
            key_id: Key ID to revoke

        Returns:
            True if key was revoked
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "UPDATE api_keys SET revoked = 1 WHERE id = ?",
            (key_id,),
        )
        await self._connection.commit()
        revoked = cursor.rowcount > 0

        if revoked:
            logger.info("api_key_revoked", key_id=key_id)

        return revoked

    async def update_api_key_last_used(self, key_id: str) -> None:
        """Update the last_used_at timestamp for an API key.

        Args:
            key_id: Key ID to update
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        now = datetime.now(timezone.utc).isoformat()
        await self._connection.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (now, key_id),
        )
        await self._connection.commit()

    # Certificate operations

    async def register_certificate(
        self,
        cert_id: str,
        agent_id: str,
        certificate_cn: str,
        fingerprint: str,
        expires_at: datetime,
    ) -> None:
        """Register a new certificate.

        Args:
            cert_id: Certificate ID
            agent_id: Agent ID
            certificate_cn: Certificate Common Name
            fingerprint: Certificate fingerprint (SHA256)
            expires_at: Expiration time
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        now = datetime.now(timezone.utc).isoformat()
        await self._connection.execute(
            """INSERT INTO certificates
               (id, agent_id, certificate_cn, fingerprint, issued_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (cert_id, agent_id, certificate_cn, fingerprint, now, expires_at.isoformat()),
        )
        await self._connection.commit()
        logger.info("certificate_registered", cert_id=cert_id, agent_id=agent_id)

    async def verify_certificate(self, certificate_cn: str) -> Certificate | None:
        """Verify a certificate by CN.

        Args:
            certificate_cn: Certificate Common Name

        Returns:
            Certificate if valid, None otherwise
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            """SELECT * FROM certificates
               WHERE certificate_cn = ? AND revoked = 0""",
            (certificate_cn,),
        )
        row = await cursor.fetchone()

        if not row:
            return None

        # Check expiration
        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.now(timezone.utc) > expires:
            return None

        return Certificate(
            id=row["id"],
            agent_id=row["agent_id"],
            certificate_cn=row["certificate_cn"],
            fingerprint=row["fingerprint"],
            issued_at=datetime.fromisoformat(row["issued_at"]),
            expires_at=expires,
            revoked=bool(row["revoked"]),
            revoked_at=datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None,
            revoked_reason=row["revoked_reason"],
        )

    async def revoke_certificate(self, cert_id: str, reason: str = "") -> bool:
        """Revoke a certificate.

        Args:
            cert_id: Certificate ID to revoke
            reason: Revocation reason

        Returns:
            True if certificate was revoked
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        now = datetime.now(timezone.utc).isoformat()
        cursor = await self._connection.execute(
            """UPDATE certificates
               SET revoked = 1, revoked_at = ?, revoked_reason = ?
               WHERE id = ?""",
            (now, reason, cert_id),
        )
        await self._connection.commit()
        revoked = cursor.rowcount > 0

        if revoked:
            logger.info("certificate_revoked", cert_id=cert_id, reason=reason)

        return revoked

    # Provisioning token operations

    async def create_provisioning_token(
        self,
        token_hash: str,
        client_id: str,
        client_name: str | None = None,
        tier: str = "starter",
        hosting_type: str = "self_hosted",
        expires_at: datetime | None = None,
        max_agents: int = 1,
        created_by: str = "system",
    ) -> None:
        """Create a provisioning token.

        Args:
            token_hash: SHA256 hash of the token
            client_id: Client ID
            client_name: Client name
            tier: Tier for provisioned agents
            hosting_type: self_hosted or aseoka_hosted
            expires_at: Expiration time
            max_agents: Maximum agents this token can provision
            created_by: Who created the token
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        now = datetime.now(timezone.utc)
        expires = expires_at or (now + timedelta(hours=24))

        await self._connection.execute(
            """INSERT INTO provisioning_tokens
               (token_hash, client_id, client_name, tier, hosting_type,
                created_at, expires_at, max_agents, agents_created, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)""",
            (
                token_hash,
                client_id,
                client_name,
                tier,
                hosting_type,
                now.isoformat(),
                expires.isoformat(),
                max_agents,
                created_by,
            ),
        )
        await self._connection.commit()
        logger.info("provisioning_token_created", client_id=client_id)

    async def get_provisioning_token(self, token_hash: str) -> ProvisioningToken | None:
        """Get a provisioning token by its hash.

        Args:
            token_hash: SHA256 hash of the token

        Returns:
            ProvisioningToken if found, None otherwise
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "SELECT * FROM provisioning_tokens WHERE token_hash = ?",
            (token_hash,),
        )
        row = await cursor.fetchone()

        if not row:
            return None

        return ProvisioningToken(
            token_hash=row["token_hash"],
            client_id=row["client_id"],
            client_name=row["client_name"],
            tier=row["tier"],
            hosting_type=row["hosting_type"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            max_agents=row["max_agents"],
            agents_created=row["agents_created"],
            created_by=row["created_by"] or "system",
        )

    async def validate_provisioning_token(
        self, token_hash: str
    ) -> tuple[bool, str, ProvisioningToken | None]:
        """Validate a provisioning token.

        Args:
            token_hash: SHA256 hash of the token

        Returns:
            Tuple of (is_valid, error_message, token_data)
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "SELECT * FROM provisioning_tokens WHERE token_hash = ?",
            (token_hash,),
        )
        row = await cursor.fetchone()

        if not row:
            return False, "Invalid provisioning token", None

        # Check expiration
        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.now(timezone.utc) > expires:
            return False, "Provisioning token expired", None

        # Check agent limit
        if row["agents_created"] >= row["max_agents"]:
            return (
                False,
                f"Maximum agents ({row['max_agents']}) already created with this token",
                None,
            )

        token = ProvisioningToken(
            token_hash=row["token_hash"],
            client_id=row["client_id"],
            client_name=row["client_name"],
            tier=row["tier"],
            hosting_type=row["hosting_type"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            expires_at=expires,
            max_agents=row["max_agents"],
            agents_created=row["agents_created"],
            created_by=row["created_by"] or "system",
        )

        return True, "", token

    async def increment_token_usage(self, token_hash: str) -> None:
        """Increment the agents_created count for a token.

        Args:
            token_hash: Token hash to update
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        await self._connection.execute(
            "UPDATE provisioning_tokens SET agents_created = agents_created + 1 WHERE token_hash = ?",
            (token_hash,),
        )
        await self._connection.commit()

    async def delete_provisioning_token(self, token_hash: str) -> bool:
        """Delete a provisioning token.

        Args:
            token_hash: Token hash to delete

        Returns:
            True if token was deleted
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "DELETE FROM provisioning_tokens WHERE token_hash = ?",
            (token_hash,),
        )
        await self._connection.commit()

        return cursor.rowcount > 0

    # Log operations

    async def ingest_logs(self, entries: list[LogEntry]) -> int:
        """Ingest a batch of log entries from an agent.

        Args:
            entries: List of log entries to store

        Returns:
            Number of entries successfully stored
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        if not entries:
            return 0

        now = datetime.now(timezone.utc).isoformat()
        count = 0

        for entry in entries:
            try:
                context_json = json.dumps(entry.context) if entry.context else None
                timestamp = entry.timestamp.isoformat() if entry.timestamp else now

                await self._connection.execute(
                    """INSERT OR IGNORE INTO agent_logs
                       (log_id, agent_id, level, logger_name, message, context, timestamp, received_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.log_id,
                        entry.agent_id,
                        entry.level,
                        entry.logger_name,
                        entry.message,
                        context_json,
                        timestamp,
                        now,
                    ),
                )
                count += 1
            except Exception as e:
                logger.warning("log_ingest_failed", log_id=entry.log_id, error=str(e))

        await self._connection.commit()
        logger.debug("logs_ingested", count=count, agent_id=entries[0].agent_id if entries else None)

        return count

    async def query_logs(
        self,
        agent_id: str | None = None,
        level: str | None = None,
        logger_name: str | None = None,
        search: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[LogEntry]:
        """Query logs with optional filters.

        Args:
            agent_id: Filter by agent ID
            level: Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            logger_name: Filter by logger name
            search: Search in message text
            since: Only logs after this timestamp
            until: Only logs before this timestamp
            limit: Maximum number of entries to return
            offset: Number of entries to skip

        Returns:
            List of matching log entries
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        query = "SELECT * FROM agent_logs WHERE 1=1"
        params: list = []

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        if level:
            query += " AND level = ?"
            params.append(level.upper())

        if logger_name:
            query += " AND logger_name LIKE ?"
            params.append(f"%{logger_name}%")

        if search:
            query += " AND message LIKE ?"
            params.append(f"%{search}%")

        if since:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())

        if until:
            query += " AND timestamp <= ?"
            params.append(until.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = await self._connection.execute(query, params)
        rows = await cursor.fetchall()

        return [self._row_to_log_entry(row) for row in rows]

    async def get_log_stats(self, agent_id: str) -> dict[str, int]:
        """Get log statistics for an agent.

        Args:
            agent_id: Agent ID

        Returns:
            Dict with counts per log level
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            """SELECT level, COUNT(*) as count
               FROM agent_logs
               WHERE agent_id = ?
               GROUP BY level""",
            (agent_id,),
        )
        rows = await cursor.fetchall()

        stats = {"DEBUG": 0, "INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
        for row in rows:
            stats[row["level"]] = row["count"]

        return stats

    async def delete_old_logs(self, older_than: datetime) -> int:
        """Delete logs older than specified timestamp.

        Args:
            older_than: Delete logs before this timestamp

        Returns:
            Number of logs deleted
        """
        if not self._connection:
            raise RuntimeError("Database not connected")

        cursor = await self._connection.execute(
            "DELETE FROM agent_logs WHERE timestamp < ?",
            (older_than.isoformat(),),
        )
        await self._connection.commit()

        deleted = cursor.rowcount
        if deleted > 0:
            logger.info("old_logs_deleted", count=deleted)

        return deleted

    def _row_to_log_entry(self, row: aiosqlite.Row) -> LogEntry:
        """Convert database row to LogEntry.

        Args:
            row: Database row

        Returns:
            LogEntry object
        """
        context = json.loads(row["context"]) if row["context"] else None

        return LogEntry(
            log_id=row["log_id"],
            agent_id=row["agent_id"],
            level=row["level"],
            logger_name=row["logger_name"],
            message=row["message"],
            context=context,
            timestamp=datetime.fromisoformat(row["timestamp"]) if row["timestamp"] else None,
            received_at=datetime.fromisoformat(row["received_at"]) if row["received_at"] else None,
        )
