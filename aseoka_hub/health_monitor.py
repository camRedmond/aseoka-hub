"""Health monitor for ASEOKA Hub.

Monitors agent health and creates alerts for unhealthy agents.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Callable, Awaitable

from aseoka_hub.database import HubDatabase, Alert, Agent
from aseoka_hub.types import generate_id
from aseoka_hub.logging import get_logger

logger = get_logger(__name__)


# Alert types
ALERT_OFFLINE = "offline"
ALERT_STALE_HEARTBEAT = "stale_heartbeat"
ALERT_LOW_HEALTH = "low_health"
ALERT_HIGH_ERRORS = "high_errors"


class HealthMonitor:
    """Monitors agent health and creates alerts.

    Configuration:
        - offline_threshold: Minutes without heartbeat before agent is considered offline
        - stale_threshold: Minutes without heartbeat before warning
        - low_health_threshold: Health score below this triggers warning
        - critical_health_threshold: Health score below this triggers critical alert
        - check_interval: Seconds between health checks
    """

    def __init__(
        self,
        database: HubDatabase,
        offline_threshold_minutes: int = 10,
        stale_threshold_minutes: int = 5,
        low_health_threshold: int = 50,
        critical_health_threshold: int = 20,
        check_interval_seconds: int = 60,
        on_alert_created: Callable[[Alert], Awaitable[None]] | None = None,
    ):
        """Initialize health monitor.

        Args:
            database: Hub database instance
            offline_threshold_minutes: Minutes without heartbeat to mark offline
            stale_threshold_minutes: Minutes without heartbeat to warn
            low_health_threshold: Health score for warning alert
            critical_health_threshold: Health score for critical alert
            check_interval_seconds: Seconds between checks
            on_alert_created: Optional callback when alert is created
        """
        self.db = database
        self.offline_threshold = timedelta(minutes=offline_threshold_minutes)
        self.stale_threshold = timedelta(minutes=stale_threshold_minutes)
        self.low_health_threshold = low_health_threshold
        self.critical_health_threshold = critical_health_threshold
        self.check_interval = check_interval_seconds
        self.on_alert_created = on_alert_created

        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the health monitor background task."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info(
            "health_monitor_started",
            check_interval=self.check_interval,
            offline_threshold_min=self.offline_threshold.total_seconds() / 60,
        )

    async def stop(self) -> None:
        """Stop the health monitor."""
        self._running = False

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        logger.info("health_monitor_stopped")

    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                await self._check_all_agents()
            except Exception as e:
                logger.error("health_check_failed", error=str(e))

            await asyncio.sleep(self.check_interval)

    async def _check_all_agents(self) -> None:
        """Check health of all agents."""
        agents = await self.db.get_all_agents()
        now = datetime.now(timezone.utc)

        for agent in agents:
            await self._check_agent(agent, now)

    async def _check_agent(self, agent: Agent, now: datetime) -> None:
        """Check health of a single agent.

        Args:
            agent: Agent to check
            now: Current timestamp
        """
        # Check heartbeat freshness
        if agent.last_heartbeat:
            time_since_heartbeat = now - agent.last_heartbeat

            # Check for offline
            if time_since_heartbeat > self.offline_threshold:
                await self._create_alert_if_needed(
                    agent_id=agent.agent_id,
                    alert_type=ALERT_OFFLINE,
                    severity="critical",
                    title=f"Agent offline: {agent.site_name}",
                    description=f"No heartbeat received for {int(time_since_heartbeat.total_seconds() / 60)} minutes",
                    metadata={
                        "last_heartbeat": agent.last_heartbeat.isoformat(),
                        "site_url": agent.site_url,
                    },
                )
            # Check for stale heartbeat (warning before offline)
            elif time_since_heartbeat > self.stale_threshold:
                await self._create_alert_if_needed(
                    agent_id=agent.agent_id,
                    alert_type=ALERT_STALE_HEARTBEAT,
                    severity="warning",
                    title=f"Agent heartbeat stale: {agent.site_name}",
                    description=f"No heartbeat for {int(time_since_heartbeat.total_seconds() / 60)} minutes",
                    metadata={
                        "last_heartbeat": agent.last_heartbeat.isoformat(),
                        "site_url": agent.site_url,
                    },
                )
            else:
                # Agent is healthy - resolve any stale/offline alerts
                await self._resolve_alerts(agent.agent_id, [ALERT_OFFLINE, ALERT_STALE_HEARTBEAT])
        else:
            # Never received heartbeat - create offline alert
            await self._create_alert_if_needed(
                agent_id=agent.agent_id,
                alert_type=ALERT_OFFLINE,
                severity="critical",
                title=f"Agent never connected: {agent.site_name}",
                description="Agent has never sent a heartbeat",
                metadata={"site_url": agent.site_url},
            )

        # Check health score
        if agent.health_score < self.critical_health_threshold:
            await self._create_alert_if_needed(
                agent_id=agent.agent_id,
                alert_type=ALERT_LOW_HEALTH,
                severity="critical",
                title=f"Critical health score: {agent.site_name}",
                description=f"Health score is {agent.health_score}% (critical threshold: {self.critical_health_threshold}%)",
                metadata={
                    "health_score": agent.health_score,
                    "active_issues": agent.active_issues,
                    "site_url": agent.site_url,
                },
            )
        elif agent.health_score < self.low_health_threshold:
            await self._create_alert_if_needed(
                agent_id=agent.agent_id,
                alert_type=ALERT_LOW_HEALTH,
                severity="warning",
                title=f"Low health score: {agent.site_name}",
                description=f"Health score is {agent.health_score}% (warning threshold: {self.low_health_threshold}%)",
                metadata={
                    "health_score": agent.health_score,
                    "active_issues": agent.active_issues,
                    "site_url": agent.site_url,
                },
            )
        else:
            # Health is good - resolve any low health alerts
            await self._resolve_alerts(agent.agent_id, [ALERT_LOW_HEALTH])

    async def _create_alert_if_needed(
        self,
        agent_id: str,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        metadata: dict | None = None,
    ) -> bool:
        """Create an alert if one doesn't already exist.

        Args:
            agent_id: Agent ID
            alert_type: Type of alert
            severity: Alert severity
            title: Alert title
            description: Alert description
            metadata: Optional metadata

        Returns:
            True if alert was created
        """
        # Check if there's already an active alert of this type
        existing = await self.db.get_active_alert_for_agent(agent_id, alert_type)
        if existing:
            return False

        # Create new alert
        alert = Alert(
            alert_id=generate_id("alert"),
            agent_id=agent_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            triggered_at=datetime.now(timezone.utc),
            metadata=metadata,
        )

        await self.db.create_alert(alert)

        # Call callback if provided
        if self.on_alert_created:
            try:
                await self.on_alert_created(alert)
            except Exception as e:
                logger.error("alert_callback_failed", error=str(e))

        return True

    async def _resolve_alerts(self, agent_id: str, alert_types: list[str]) -> int:
        """Resolve active alerts of specified types for an agent.

        Args:
            agent_id: Agent ID
            alert_types: Types of alerts to resolve

        Returns:
            Number of alerts resolved
        """
        resolved = 0
        for alert_type in alert_types:
            alert = await self.db.get_active_alert_for_agent(agent_id, alert_type)
            if alert:
                if await self.db.resolve_alert(alert.alert_id):
                    resolved += 1

        return resolved

    async def check_now(self) -> None:
        """Trigger an immediate health check."""
        await self._check_all_agents()

    @property
    def is_running(self) -> bool:
        """Check if monitor is running."""
        return self._running
