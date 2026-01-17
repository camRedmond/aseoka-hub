"""Shared type definitions for ASEOKA.

This module is shared between the hub and agent packages.
Use scripts/sync-shared.sh to copy to both packages.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Literal
from uuid import uuid4


class ScanType(str, Enum):
    """Scan type enumeration."""

    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


class IssueSeverity(str, Enum):
    """Issue severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IssueType(str, Enum):
    """SEO issue types."""

    # Meta Tags
    MISSING_TITLE = "missing_title"
    TITLE_TOO_SHORT = "title_too_short"
    TITLE_TOO_LONG = "title_too_long"
    MISSING_DESCRIPTION = "missing_description"
    DESCRIPTION_TOO_SHORT = "description_too_short"
    DESCRIPTION_TOO_LONG = "description_too_long"
    MISSING_CANONICAL = "missing_canonical"
    MISSING_OG_TITLE = "missing_og_title"
    MISSING_OG_DESCRIPTION = "missing_og_description"
    MISSING_OG_IMAGE = "missing_og_image"

    # Headings
    MISSING_H1 = "missing_h1"
    MULTIPLE_H1 = "multiple_h1"
    H1_TOO_LONG = "h1_too_long"
    HEADING_HIERARCHY_BROKEN = "heading_hierarchy_broken"

    # Content
    THIN_CONTENT = "thin_content"
    DUPLICATE_CONTENT = "duplicate_content"
    LOW_READABILITY = "low_readability"
    KEYWORD_STUFFING = "keyword_stuffing"

    # Links
    BROKEN_INTERNAL_LINK = "broken_internal_link"
    BROKEN_EXTERNAL_LINK = "broken_external_link"
    REDIRECT_CHAIN = "redirect_chain"
    ORPHAN_PAGE = "orphan_page"
    TOO_MANY_LINKS = "too_many_links"
    NOFOLLOW_INTERNAL = "nofollow_internal"

    # Images
    MISSING_ALT_TEXT = "missing_alt_text"
    EMPTY_ALT_TEXT = "empty_alt_text"
    LARGE_IMAGE = "large_image"
    MISSING_IMAGE_DIMENSIONS = "missing_image_dimensions"

    # Technical
    MISSING_SITEMAP = "missing_sitemap"
    MISSING_ROBOTS = "missing_robots"
    ROBOTS_BLOCKS_ALL = "robots_blocks_all"
    MISSING_VIEWPORT = "missing_viewport"
    MISSING_LANGUAGE = "missing_language"
    MISSING_CHARSET = "missing_charset"
    INVALID_HTML = "invalid_html"

    # Performance
    SLOW_PAGE_SPEED = "slow_page_speed"
    LARGE_PAGE_SIZE = "large_page_size"
    RENDER_BLOCKING_RESOURCES = "render_blocking_resources"
    UNCOMPRESSED_RESOURCES = "uncompressed_resources"
    NO_BROWSER_CACHING = "no_browser_caching"

    # Mobile
    NOT_MOBILE_FRIENDLY = "not_mobile_friendly"
    TOUCH_ELEMENTS_TOO_CLOSE = "touch_elements_too_close"
    FONT_SIZE_TOO_SMALL = "font_size_too_small"
    CONTENT_WIDER_THAN_SCREEN = "content_wider_than_screen"

    # Structured Data
    MISSING_SCHEMA = "missing_schema"
    INVALID_SCHEMA = "invalid_schema"
    MISSING_ARTICLE_SCHEMA = "missing_article_schema"
    MISSING_PRODUCT_SCHEMA = "missing_product_schema"
    MISSING_BREADCRUMB_SCHEMA = "missing_breadcrumb_schema"
    MISSING_FAQ_SCHEMA = "missing_faq_schema"

    # Security
    MISSING_HTTPS = "missing_https"
    MIXED_CONTENT = "mixed_content"
    MISSING_HSTS = "missing_hsts"
    INSECURE_FORMS = "insecure_forms"

    # Social
    MISSING_TWITTER_CARD = "missing_twitter_card"
    MISSING_TWITTER_IMAGE = "missing_twitter_image"
    MISSING_FACEBOOK_APP_ID = "missing_facebook_app_id"

    # Indexing
    NOINDEX_IN_SITEMAP = "noindex_in_sitemap"
    CANONICAL_MISMATCH = "canonical_mismatch"
    HREFLANG_ERRORS = "hreflang_errors"
    PAGINATION_ISSUES = "pagination_issues"


class IssueCategory(str, Enum):
    """Issue category enumeration."""

    META_TAGS = "meta_tags"
    HEADINGS = "headings"
    CONTENT = "content"
    LINKS = "links"
    IMAGES = "images"
    TECHNICAL = "technical"
    STRUCTURED_DATA = "structured_data"
    PERFORMANCE = "performance"
    MOBILE = "mobile"
    SECURITY = "security"
    SOCIAL = "social"
    INDEXING = "indexing"


class ConfidenceLevel(str, Enum):
    """Fix confidence levels."""

    HIGH = "high"  # > 70%
    MEDIUM = "medium"  # 50-70%
    LOW = "low"  # 30-50%
    VERY_LOW = "very_low"  # < 30%


class FixStatus(str, Enum):
    """Fix status enumeration."""

    PENDING = "pending"
    FIXING = "fixing"
    FIXED = "fixed"
    VALIDATED = "validated"
    FAILED = "failed"
    IGNORED = "ignored"


class PRStatus(str, Enum):
    """Pull request status."""

    OPEN = "open"
    MERGED = "merged"
    REJECTED = "rejected"
    CLOSED = "closed"


def generate_id(prefix: str = "") -> str:
    """Generate a unique ID.

    Args:
        prefix: Optional prefix for the ID

    Returns:
        Unique ID string
    """
    uid = uuid4().hex[:12]
    return f"{prefix}_{uid}" if prefix else uid


@dataclass
class PageData:
    """Data about a crawled page."""

    url: str
    title: str | None = None
    description: str | None = None
    h1_tags: list[str] = field(default_factory=list)
    word_count: int = 0
    status_code: int = 200
    content_type: str = "text/html"
    canonical_url: str | None = None
    html: str = ""
    crawled_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RawFinding:
    """A raw finding from a scanner."""

    issue_type: IssueType
    severity: IssueSeverity
    url: str
    description: str
    current_value: str | None = None
    expected_value: str | None = None
    element: str | None = None


@dataclass
class Issue:
    """A categorized and prioritized SEO issue."""

    issue_id: str
    issue_type: IssueType
    category: IssueCategory
    severity: IssueSeverity
    status: FixStatus = FixStatus.PENDING
    priority_score: int = 0
    affected_urls: list[str] = field(default_factory=list)
    affected_files: dict[str, list[str]] = field(default_factory=dict)
    current_values: dict[str, str] = field(default_factory=dict)
    playbook_entry_id: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class FileChange:
    """A file change for a fix."""

    file_path: str
    original_content: str
    new_content: str
    diff: str = ""


@dataclass
class GeneratedFix:
    """A generated fix for an issue."""

    fix_id: str
    issue_id: str
    file_changes: list[FileChange]
    confidence_score: int  # 0-100
    confidence_level: ConfidenceLevel
    source: Literal["playbook", "llm"]
    explanation: str = ""
    sandbox_validated: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    # Batch tracking for multi-file fixes
    total_affected_files: int = 0  # Total files affected by the issue
    batch_number: int = 1  # Which batch this fix is (1, 2, 3...)
    files_remaining: int = 0  # Files still needing fixes after this batch


@dataclass
class ScanResult:
    """Result of a scan operation."""

    scan_id: str
    scan_type: ScanType
    site_url: str
    pages: list[PageData]
    findings: list[RawFinding]
    pages_crawled: int = 0
    issues_found: int = 0
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    duration_seconds: float = 0.0


@dataclass
class AnalysisResult:
    """Result of analysis phase."""

    issues: list[Issue]
    health_score: int  # 0-100
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


@dataclass
class FixDecision:
    """Decision about whether to fix an issue."""

    issue_id: str
    should_fix: bool
    reasoning: str
    priority: int = 0


@dataclass
class FixDecisionSet:
    """Set of fix decisions from reasoning phase."""

    decisions: list[FixDecision]
    reasoning_summary: str = ""
    tokens_used: int = 0


# =============================================================================
# Playbook Data Types (used by both hub and agent)
# =============================================================================


@dataclass
class CodeExample:
    """Before/after code example."""

    before: str
    after: str
    description: str = ""


@dataclass
class PlaybookEntryData:
    """Playbook entry data for hub-agent communication.

    This is a data-only class used for transferring playbook entries
    between the hub and agent. It contains no database methods.
    """

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


@dataclass
class PlaybookOutcomeData:
    """Playbook outcome data for reporting fix results."""

    outcome_id: str
    entry_id: str
    agent_id: str
    issue_id: str
    pr_url: str | None = None
    outcome: Literal["success", "failure", "pending"] = "pending"
    failure_reason: str | None = None


# =============================================================================
# Hub-Agent Communication Types
# =============================================================================


@dataclass
class BootstrapRequest:
    """Agent bootstrap request."""

    provisioning_token: str
    site_url: str
    site_name: str
    platform: str | None = None
    hostname: str | None = None


@dataclass
class BootstrapResponse:
    """Agent bootstrap response with credentials."""

    agent_id: str
    client_id: str
    api_key: str
    jwt_token: str
    hub_url: str
    site_url: str
    certificate: str | None = None
    private_key: str | None = None
    ca_cert: str | None = None


@dataclass
class HeartbeatData:
    """Agent heartbeat data."""

    agent_id: str
    health_score: int = 0
    active_issues: int = 0
    pending_fixes: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0


@dataclass
class ActivityData:
    """Agent activity data."""

    activity_type: str
    description: str = ""
    metadata: dict = field(default_factory=dict)


# =============================================================================
# Mappings and Constants
# =============================================================================


# Issue type to category mapping
ISSUE_CATEGORY_MAP: dict[IssueType, IssueCategory] = {
    # Meta Tags
    IssueType.MISSING_TITLE: IssueCategory.META_TAGS,
    IssueType.TITLE_TOO_SHORT: IssueCategory.META_TAGS,
    IssueType.TITLE_TOO_LONG: IssueCategory.META_TAGS,
    IssueType.MISSING_DESCRIPTION: IssueCategory.META_TAGS,
    IssueType.DESCRIPTION_TOO_SHORT: IssueCategory.META_TAGS,
    IssueType.DESCRIPTION_TOO_LONG: IssueCategory.META_TAGS,
    IssueType.MISSING_CANONICAL: IssueCategory.META_TAGS,
    IssueType.MISSING_OG_TITLE: IssueCategory.META_TAGS,
    IssueType.MISSING_OG_DESCRIPTION: IssueCategory.META_TAGS,
    IssueType.MISSING_OG_IMAGE: IssueCategory.META_TAGS,
    # Headings
    IssueType.MISSING_H1: IssueCategory.HEADINGS,
    IssueType.MULTIPLE_H1: IssueCategory.HEADINGS,
    IssueType.H1_TOO_LONG: IssueCategory.HEADINGS,
    IssueType.HEADING_HIERARCHY_BROKEN: IssueCategory.HEADINGS,
    # Content
    IssueType.THIN_CONTENT: IssueCategory.CONTENT,
    IssueType.DUPLICATE_CONTENT: IssueCategory.CONTENT,
    IssueType.LOW_READABILITY: IssueCategory.CONTENT,
    IssueType.KEYWORD_STUFFING: IssueCategory.CONTENT,
    # Links
    IssueType.BROKEN_INTERNAL_LINK: IssueCategory.LINKS,
    IssueType.BROKEN_EXTERNAL_LINK: IssueCategory.LINKS,
    IssueType.REDIRECT_CHAIN: IssueCategory.LINKS,
    IssueType.ORPHAN_PAGE: IssueCategory.LINKS,
    IssueType.TOO_MANY_LINKS: IssueCategory.LINKS,
    IssueType.NOFOLLOW_INTERNAL: IssueCategory.LINKS,
    # Images
    IssueType.MISSING_ALT_TEXT: IssueCategory.IMAGES,
    IssueType.EMPTY_ALT_TEXT: IssueCategory.IMAGES,
    IssueType.LARGE_IMAGE: IssueCategory.IMAGES,
    IssueType.MISSING_IMAGE_DIMENSIONS: IssueCategory.IMAGES,
    # Technical
    IssueType.MISSING_SITEMAP: IssueCategory.TECHNICAL,
    IssueType.MISSING_ROBOTS: IssueCategory.TECHNICAL,
    IssueType.ROBOTS_BLOCKS_ALL: IssueCategory.TECHNICAL,
    IssueType.MISSING_VIEWPORT: IssueCategory.TECHNICAL,
    IssueType.MISSING_LANGUAGE: IssueCategory.TECHNICAL,
    IssueType.MISSING_CHARSET: IssueCategory.TECHNICAL,
    IssueType.INVALID_HTML: IssueCategory.TECHNICAL,
    # Performance
    IssueType.SLOW_PAGE_SPEED: IssueCategory.PERFORMANCE,
    IssueType.LARGE_PAGE_SIZE: IssueCategory.PERFORMANCE,
    IssueType.RENDER_BLOCKING_RESOURCES: IssueCategory.PERFORMANCE,
    IssueType.UNCOMPRESSED_RESOURCES: IssueCategory.PERFORMANCE,
    IssueType.NO_BROWSER_CACHING: IssueCategory.PERFORMANCE,
    # Mobile
    IssueType.NOT_MOBILE_FRIENDLY: IssueCategory.MOBILE,
    IssueType.TOUCH_ELEMENTS_TOO_CLOSE: IssueCategory.MOBILE,
    IssueType.FONT_SIZE_TOO_SMALL: IssueCategory.MOBILE,
    IssueType.CONTENT_WIDER_THAN_SCREEN: IssueCategory.MOBILE,
    # Structured Data
    IssueType.MISSING_SCHEMA: IssueCategory.STRUCTURED_DATA,
    IssueType.INVALID_SCHEMA: IssueCategory.STRUCTURED_DATA,
    IssueType.MISSING_ARTICLE_SCHEMA: IssueCategory.STRUCTURED_DATA,
    IssueType.MISSING_PRODUCT_SCHEMA: IssueCategory.STRUCTURED_DATA,
    IssueType.MISSING_BREADCRUMB_SCHEMA: IssueCategory.STRUCTURED_DATA,
    IssueType.MISSING_FAQ_SCHEMA: IssueCategory.STRUCTURED_DATA,
    # Security
    IssueType.MISSING_HTTPS: IssueCategory.SECURITY,
    IssueType.MIXED_CONTENT: IssueCategory.SECURITY,
    IssueType.MISSING_HSTS: IssueCategory.SECURITY,
    IssueType.INSECURE_FORMS: IssueCategory.SECURITY,
    # Social
    IssueType.MISSING_TWITTER_CARD: IssueCategory.SOCIAL,
    IssueType.MISSING_TWITTER_IMAGE: IssueCategory.SOCIAL,
    IssueType.MISSING_FACEBOOK_APP_ID: IssueCategory.SOCIAL,
    # Indexing
    IssueType.NOINDEX_IN_SITEMAP: IssueCategory.INDEXING,
    IssueType.CANONICAL_MISMATCH: IssueCategory.INDEXING,
    IssueType.HREFLANG_ERRORS: IssueCategory.INDEXING,
    IssueType.PAGINATION_ISSUES: IssueCategory.INDEXING,
}

# Severity weights for priority scoring
SEVERITY_WEIGHTS: dict[IssueSeverity, int] = {
    IssueSeverity.CRITICAL: 100,
    IssueSeverity.HIGH: 75,
    IssueSeverity.MEDIUM: 50,
    IssueSeverity.LOW: 25,
}
