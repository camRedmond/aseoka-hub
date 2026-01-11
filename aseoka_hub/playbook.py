"""Playbook management for ASEOKA Hub."""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Literal

import aiosqlite

from aseoka_hub.logging import get_logger
from aseoka_hub.types import generate_id

logger = get_logger(__name__)


@dataclass
class CodeExample:
    """Before/after code example."""

    before: str
    after: str
    description: str = ""


@dataclass
class PlaybookEntry:
    """A solved SEO problem with its solution."""

    entry_id: str
    issue_type: str
    category: str
    severity: str
    title: str
    description: str = ""
    fix_description: str = ""
    fix_steps: list[str] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)
    anti_patterns: list[str] = field(default_factory=list)
    code_examples: dict[str, CodeExample] = field(default_factory=dict)
    file_patterns: dict[str, list[str]] = field(default_factory=dict)
    success_count: int = 0
    failure_count: int = 0
    success_rate: float = 0.0
    created_at: datetime | None = None
    updated_at: datetime | None = None
    created_by: str = "system"
    last_modified_by: str = "system"


@dataclass
class PlaybookOutcome:
    """Outcome of applying a playbook entry."""

    outcome_id: str
    entry_id: str
    agent_id: str
    issue_id: str
    pr_url: str | None = None
    outcome: Literal["success", "failure", "pending"] = "pending"
    failure_reason: str | None = None
    created_at: datetime | None = None


# Playbook schema SQL
PLAYBOOK_SCHEMA = """
-- Playbook Entries
CREATE TABLE IF NOT EXISTS playbook_entries (
    entry_id TEXT PRIMARY KEY,
    issue_type TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    fix_description TEXT,
    fix_steps TEXT,
    patterns TEXT,
    anti_patterns TEXT,
    code_examples TEXT,
    file_patterns TEXT,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    success_rate REAL DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT,
    last_modified_by TEXT,
    UNIQUE(issue_type, category)
);

-- Playbook Outcomes
CREATE TABLE IF NOT EXISTS playbook_outcomes (
    outcome_id TEXT PRIMARY KEY,
    entry_id TEXT REFERENCES playbook_entries(entry_id),
    agent_id TEXT,
    issue_id TEXT,
    pr_url TEXT,
    outcome TEXT NOT NULL,
    failure_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_playbook_issue_type ON playbook_entries(issue_type);
CREATE INDEX IF NOT EXISTS idx_playbook_category ON playbook_entries(category);
CREATE INDEX IF NOT EXISTS idx_outcomes_entry ON playbook_outcomes(entry_id);
CREATE INDEX IF NOT EXISTS idx_outcomes_agent ON playbook_outcomes(agent_id);
"""


class PlaybookManager:
    """Manage playbook entries and outcomes."""

    def __init__(self, connection: aiosqlite.Connection):
        """Initialize playbook manager.

        Args:
            connection: Database connection
        """
        self._connection = connection

    async def init_schema(self) -> None:
        """Initialize playbook schema."""
        statements = [s.strip() for s in PLAYBOOK_SCHEMA.split(";") if s.strip()]
        for statement in statements:
            await self._connection.execute(statement)
        await self._connection.commit()

    # Entry operations

    async def create_entry(self, entry: PlaybookEntry) -> None:
        """Create a new playbook entry.

        Args:
            entry: Entry to create
        """
        now = datetime.now(timezone.utc).isoformat()

        # Serialize complex fields
        fix_steps_json = json.dumps(entry.fix_steps)
        patterns_json = json.dumps(entry.patterns)
        anti_patterns_json = json.dumps(entry.anti_patterns)
        code_examples_json = json.dumps(
            {k: asdict(v) for k, v in entry.code_examples.items()}
        )
        file_patterns_json = json.dumps(entry.file_patterns)

        await self._connection.execute(
            """INSERT INTO playbook_entries
               (entry_id, issue_type, category, severity, title, description,
                fix_description, fix_steps, patterns, anti_patterns, code_examples,
                file_patterns, success_count, failure_count, success_rate,
                created_at, updated_at, created_by, last_modified_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.entry_id,
                entry.issue_type,
                entry.category,
                entry.severity,
                entry.title,
                entry.description,
                entry.fix_description,
                fix_steps_json,
                patterns_json,
                anti_patterns_json,
                code_examples_json,
                file_patterns_json,
                entry.success_count,
                entry.failure_count,
                entry.success_rate,
                now,
                now,
                entry.created_by,
                entry.last_modified_by,
            ),
        )
        await self._connection.commit()
        logger.info("playbook_entry_created", entry_id=entry.entry_id)

    async def get_entry(self, entry_id: str) -> PlaybookEntry | None:
        """Get a playbook entry by ID.

        Args:
            entry_id: Entry ID

        Returns:
            PlaybookEntry or None
        """
        cursor = await self._connection.execute(
            "SELECT * FROM playbook_entries WHERE entry_id = ?",
            (entry_id,),
        )
        row = await cursor.fetchone()

        if not row:
            return None

        return self._row_to_entry(row)

    async def query_entries(
        self,
        issue_type: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[PlaybookEntry]:
        """Query playbook entries with filters.

        Args:
            issue_type: Filter by issue type
            category: Filter by category
            severity: Filter by severity
            limit: Maximum entries to return

        Returns:
            List of matching entries
        """
        query = "SELECT * FROM playbook_entries WHERE 1=1"
        params: list = []

        if issue_type:
            query += " AND issue_type = ?"
            params.append(issue_type)

        if category:
            query += " AND category = ?"
            params.append(category)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY success_rate DESC, success_count DESC LIMIT ?"
        params.append(limit)

        cursor = await self._connection.execute(query, params)
        rows = await cursor.fetchall()

        return [self._row_to_entry(row) for row in rows]

    async def update_entry(
        self,
        entry_id: str,
        updates: dict,
        modified_by: str = "system",
    ) -> bool:
        """Update a playbook entry.

        Args:
            entry_id: Entry to update
            updates: Fields to update
            modified_by: Who modified it

        Returns:
            True if updated
        """
        now = datetime.now(timezone.utc).isoformat()

        # Build update query
        set_parts = ["updated_at = ?", "last_modified_by = ?"]
        params = [now, modified_by]

        for key, value in updates.items():
            if key in ("fix_steps", "patterns", "anti_patterns", "file_patterns"):
                set_parts.append(f"{key} = ?")
                params.append(json.dumps(value))
            elif key == "code_examples":
                set_parts.append(f"{key} = ?")
                params.append(json.dumps({k: asdict(v) for k, v in value.items()}))
            else:
                set_parts.append(f"{key} = ?")
                params.append(value)

        params.append(entry_id)

        cursor = await self._connection.execute(
            f"UPDATE playbook_entries SET {', '.join(set_parts)} WHERE entry_id = ?",
            params,
        )
        await self._connection.commit()

        return cursor.rowcount > 0

    def _row_to_entry(self, row: aiosqlite.Row) -> PlaybookEntry:
        """Convert database row to PlaybookEntry.

        Args:
            row: Database row

        Returns:
            PlaybookEntry
        """
        # Deserialize complex fields
        fix_steps = json.loads(row["fix_steps"]) if row["fix_steps"] else []
        patterns = json.loads(row["patterns"]) if row["patterns"] else []
        anti_patterns = json.loads(row["anti_patterns"]) if row["anti_patterns"] else []

        code_examples_raw = json.loads(row["code_examples"]) if row["code_examples"] else {}
        code_examples = {
            k: CodeExample(**v) for k, v in code_examples_raw.items()
        }

        file_patterns = json.loads(row["file_patterns"]) if row["file_patterns"] else {}

        return PlaybookEntry(
            entry_id=row["entry_id"],
            issue_type=row["issue_type"],
            category=row["category"],
            severity=row["severity"],
            title=row["title"],
            description=row["description"] or "",
            fix_description=row["fix_description"] or "",
            fix_steps=fix_steps,
            patterns=patterns,
            anti_patterns=anti_patterns,
            code_examples=code_examples,
            file_patterns=file_patterns,
            success_count=row["success_count"],
            failure_count=row["failure_count"],
            success_rate=row["success_rate"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            created_by=row["created_by"] or "system",
            last_modified_by=row["last_modified_by"] or "system",
        )

    # Outcome operations

    async def record_outcome(self, outcome: PlaybookOutcome) -> None:
        """Record a playbook outcome.

        Args:
            outcome: Outcome to record
        """
        now = datetime.now(timezone.utc).isoformat()

        await self._connection.execute(
            """INSERT INTO playbook_outcomes
               (outcome_id, entry_id, agent_id, issue_id, pr_url, outcome,
                failure_reason, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                outcome.outcome_id,
                outcome.entry_id,
                outcome.agent_id,
                outcome.issue_id,
                outcome.pr_url,
                outcome.outcome,
                outcome.failure_reason,
                now,
            ),
        )
        await self._connection.commit()

        # Update success/failure counts
        if outcome.outcome == "success":
            await self._update_success_count(outcome.entry_id, success=True)
        elif outcome.outcome == "failure":
            await self._update_success_count(outcome.entry_id, success=False)

        logger.info(
            "playbook_outcome_recorded",
            outcome_id=outcome.outcome_id,
            entry_id=outcome.entry_id,
            outcome=outcome.outcome,
        )

    async def _update_success_count(self, entry_id: str, success: bool) -> None:
        """Update success/failure count for an entry.

        Args:
            entry_id: Entry to update
            success: Whether outcome was success
        """
        if success:
            await self._connection.execute(
                """UPDATE playbook_entries
                   SET success_count = success_count + 1,
                       success_rate = CAST(success_count + 1 AS REAL) /
                                     (success_count + failure_count + 1)
                   WHERE entry_id = ?""",
                (entry_id,),
            )
        else:
            await self._connection.execute(
                """UPDATE playbook_entries
                   SET failure_count = failure_count + 1,
                       success_rate = CAST(success_count AS REAL) /
                                     (success_count + failure_count + 1)
                   WHERE entry_id = ?""",
                (entry_id,),
            )
        await self._connection.commit()

    async def get_outcomes(
        self,
        entry_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[PlaybookOutcome]:
        """Get playbook outcomes with filters.

        Args:
            entry_id: Filter by entry
            agent_id: Filter by agent
            limit: Maximum outcomes to return

        Returns:
            List of outcomes
        """
        query = "SELECT * FROM playbook_outcomes WHERE 1=1"
        params: list = []

        if entry_id:
            query += " AND entry_id = ?"
            params.append(entry_id)

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor = await self._connection.execute(query, params)
        rows = await cursor.fetchall()

        outcomes = []
        for row in rows:
            outcomes.append(
                PlaybookOutcome(
                    outcome_id=row["outcome_id"],
                    entry_id=row["entry_id"],
                    agent_id=row["agent_id"],
                    issue_id=row["issue_id"],
                    pr_url=row["pr_url"],
                    outcome=row["outcome"],
                    failure_reason=row["failure_reason"],
                    created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
                )
            )

        return outcomes

    # Helper methods

    async def get_best_entry_for_issue(self, issue_type: str) -> PlaybookEntry | None:
        """Get the best playbook entry for an issue type.

        Returns entry with highest success rate.

        Args:
            issue_type: Issue type to match

        Returns:
            Best matching entry or None
        """
        entries = await self.query_entries(issue_type=issue_type, limit=1)
        return entries[0] if entries else None

    async def contribute_entry(
        self,
        issue_type: str,
        category: str,
        severity: str,
        title: str,
        fix_description: str,
        fix_steps: list[str],
        contributed_by: str,
        patterns: list[str] | None = None,
        anti_patterns: list[str] | None = None,
        code_examples: dict[str, CodeExample] | None = None,
        file_patterns: dict[str, list[str]] | None = None,
    ) -> PlaybookEntry:
        """Contribute a new playbook entry.

        Args:
            issue_type: Issue type
            category: Issue category
            severity: Issue severity
            title: Entry title
            fix_description: How to fix
            fix_steps: Step by step instructions
            contributed_by: Agent or user contributing
            patterns: Good patterns
            anti_patterns: Bad patterns
            code_examples: Code examples by framework
            file_patterns: File patterns by framework

        Returns:
            Created entry
        """
        entry = PlaybookEntry(
            entry_id=generate_id("playbook"),
            issue_type=issue_type,
            category=category,
            severity=severity,
            title=title,
            fix_description=fix_description,
            fix_steps=fix_steps,
            patterns=patterns or [],
            anti_patterns=anti_patterns or [],
            code_examples=code_examples or {},
            file_patterns=file_patterns or {},
            created_by=contributed_by,
            last_modified_by=contributed_by,
        )

        await self.create_entry(entry)
        return entry
