"""Structured logging for ASEOKA.

This module is shared between the hub and agent packages.
Use scripts/sync-shared.sh to copy to both packages.
"""

import logging
import sys
import time
from typing import Any

import structlog
from structlog.typing import Processor


class HealthCheckFilter(logging.Filter):
    """Filter out noisy health check access logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter health check and heartbeat HTTP logs."""
        message = record.getMessage()
        # Filter out uvicorn access logs for health/heartbeat endpoints
        if "GET /health" in message or "POST /agents/heartbeat" in message:
            return False
        return True


class RateLimitedLogFilter(logging.Filter):
    """Rate limit repetitive log messages."""

    def __init__(self, rate_limit_seconds: float = 5.0):
        super().__init__()
        self._last_logged: dict[str, float] = {}
        self._rate_limit = rate_limit_seconds

    def filter(self, record: logging.LogRecord) -> bool:
        """Rate limit logs with same message pattern."""
        # Create a key from the log event name (structlog puts it in the message)
        message = record.getMessage()

        # Only rate limit specific noisy events
        rate_limited_events = ["mapping_not_found", "heartbeat_sent", "heartbeat_updated"]
        for event in rate_limited_events:
            if event in message:
                now = time.time()
                last_time = self._last_logged.get(event, 0)
                if now - last_time < self._rate_limit:
                    return False
                self._last_logged[event] = now
                break

        return True


def setup_logging(
    level: str = "INFO",
    format_type: str = "console",
    filter_health_checks: bool = True,
    rate_limit_noisy_logs: bool = True,
) -> None:
    """Set up structured logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        format_type: Output format (json, console)
        filter_health_checks: Whether to filter out health check access logs
        rate_limit_noisy_logs: Whether to rate limit repetitive debug logs
    """
    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper()),
    )

    # Add filters to reduce log noise
    if filter_health_checks:
        # Filter uvicorn access logs
        uvicorn_access = logging.getLogger("uvicorn.access")
        uvicorn_access.addFilter(HealthCheckFilter())

    if rate_limit_noisy_logs:
        # Rate limit structlog output
        root_logger = logging.getLogger()
        root_logger.addFilter(RateLimitedLogFilter(rate_limit_seconds=10.0))

    # Shared processors
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if format_type == "json":
        # JSON output for production
        processors: list[Processor] = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Console output for development
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.plain_traceback,
            ),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structured logger.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Configured structured logger
    """
    return structlog.get_logger(name)


def bind_context(**kwargs: Any) -> None:
    """Bind context variables for all loggers.

    Args:
        **kwargs: Context variables to bind
    """
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    """Clear all bound context variables."""
    structlog.contextvars.clear_contextvars()
