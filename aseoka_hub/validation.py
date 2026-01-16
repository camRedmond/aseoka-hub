"""Validation utilities for ASEOKA Hub.

This module provides security-focused validation functions for input data,
particularly for validating metadata and other unstructured data.
"""

from typing import Any


# =============================================================================
# Metadata Validation Configuration
# =============================================================================

# Maximum depth for nested objects
MAX_METADATA_DEPTH = 5

# Maximum number of keys at any level
MAX_METADATA_KEYS = 50

# Maximum string value length
MAX_METADATA_STRING_LENGTH = 10000

# Maximum total payload size (approximate, in characters)
MAX_METADATA_PAYLOAD_SIZE = 100000


class MetadataValidationError(ValueError):
    """Raised when metadata validation fails."""

    pass


def validate_metadata(
    metadata: Any,
    *,
    max_depth: int = MAX_METADATA_DEPTH,
    max_keys: int = MAX_METADATA_KEYS,
    max_string_length: int = MAX_METADATA_STRING_LENGTH,
    max_payload_size: int = MAX_METADATA_PAYLOAD_SIZE,
    _current_depth: int = 0,
    _total_size: list | None = None,
) -> dict[str, Any]:
    """Validate metadata to prevent abuse.

    This function validates metadata dictionaries to ensure they don't
    exceed configured limits, preventing potential DoS attacks via
    oversized payloads or deeply nested structures.

    Args:
        metadata: The metadata to validate (should be a dict or None)
        max_depth: Maximum nesting depth allowed
        max_keys: Maximum number of keys at any level
        max_string_length: Maximum length for string values
        max_payload_size: Maximum total payload size in characters
        _current_depth: Internal - current recursion depth
        _total_size: Internal - running size counter

    Returns:
        The validated metadata dict (or empty dict if None)

    Raises:
        MetadataValidationError: If validation fails
    """
    # Initialize size counter on first call
    if _total_size is None:
        _total_size = [0]

    # Handle None or empty
    if metadata is None:
        return {}

    # Must be a dict
    if not isinstance(metadata, dict):
        raise MetadataValidationError(
            f"Metadata must be a dictionary, got {type(metadata).__name__}"
        )

    # Check depth
    if _current_depth > max_depth:
        raise MetadataValidationError(
            f"Metadata exceeds maximum nesting depth of {max_depth}"
        )

    # Check key count
    if len(metadata) > max_keys:
        raise MetadataValidationError(
            f"Metadata exceeds maximum key count of {max_keys} at depth {_current_depth}"
        )

    validated = {}

    for key, value in metadata.items():
        # Validate key
        if not isinstance(key, str):
            raise MetadataValidationError(
                f"Metadata keys must be strings, got {type(key).__name__}"
            )

        if len(key) > 200:
            raise MetadataValidationError(
                f"Metadata key '{key[:50]}...' exceeds maximum length of 200"
            )

        # Track size
        _total_size[0] += len(key)
        if _total_size[0] > max_payload_size:
            raise MetadataValidationError(
                f"Metadata exceeds maximum payload size of {max_payload_size}"
            )

        # Validate value based on type
        if value is None:
            validated[key] = None

        elif isinstance(value, bool):
            # Note: bool check must come before int (bool is subclass of int)
            validated[key] = value

        elif isinstance(value, (int, float)):
            validated[key] = value
            _total_size[0] += 20  # Approximate size for numbers

        elif isinstance(value, str):
            if len(value) > max_string_length:
                raise MetadataValidationError(
                    f"Metadata string value for '{key}' exceeds maximum length of {max_string_length}"
                )
            validated[key] = value
            _total_size[0] += len(value)

        elif isinstance(value, list):
            if len(value) > max_keys:
                raise MetadataValidationError(
                    f"Metadata array for '{key}' exceeds maximum length of {max_keys}"
                )
            validated[key] = _validate_list(
                value,
                key,
                max_depth=max_depth,
                max_keys=max_keys,
                max_string_length=max_string_length,
                max_payload_size=max_payload_size,
                _current_depth=_current_depth + 1,
                _total_size=_total_size,
            )

        elif isinstance(value, dict):
            validated[key] = validate_metadata(
                value,
                max_depth=max_depth,
                max_keys=max_keys,
                max_string_length=max_string_length,
                max_payload_size=max_payload_size,
                _current_depth=_current_depth + 1,
                _total_size=_total_size,
            )

        else:
            raise MetadataValidationError(
                f"Metadata value for '{key}' has unsupported type {type(value).__name__}"
            )

        # Check total size after each value
        if _total_size[0] > max_payload_size:
            raise MetadataValidationError(
                f"Metadata exceeds maximum payload size of {max_payload_size}"
            )

    return validated


def _validate_list(
    items: list,
    parent_key: str,
    *,
    max_depth: int,
    max_keys: int,
    max_string_length: int,
    max_payload_size: int,
    _current_depth: int,
    _total_size: list,
) -> list:
    """Validate a list within metadata.

    Args:
        items: The list to validate
        parent_key: The key this list is stored under (for error messages)
        Other args: Same as validate_metadata

    Returns:
        The validated list

    Raises:
        MetadataValidationError: If validation fails
    """
    if _current_depth > max_depth:
        raise MetadataValidationError(
            f"Metadata array '{parent_key}' exceeds maximum nesting depth of {max_depth}"
        )

    validated = []

    for i, item in enumerate(items):
        if item is None:
            validated.append(None)

        elif isinstance(item, bool):
            validated.append(item)

        elif isinstance(item, (int, float)):
            validated.append(item)
            _total_size[0] += 20

        elif isinstance(item, str):
            if len(item) > max_string_length:
                raise MetadataValidationError(
                    f"Metadata string in array '{parent_key}[{i}]' exceeds maximum length of {max_string_length}"
                )
            validated.append(item)
            _total_size[0] += len(item)

        elif isinstance(item, list):
            if len(item) > max_keys:
                raise MetadataValidationError(
                    f"Nested array in '{parent_key}[{i}]' exceeds maximum length of {max_keys}"
                )
            validated.append(
                _validate_list(
                    item,
                    f"{parent_key}[{i}]",
                    max_depth=max_depth,
                    max_keys=max_keys,
                    max_string_length=max_string_length,
                    max_payload_size=max_payload_size,
                    _current_depth=_current_depth + 1,
                    _total_size=_total_size,
                )
            )

        elif isinstance(item, dict):
            validated.append(
                validate_metadata(
                    item,
                    max_depth=max_depth,
                    max_keys=max_keys,
                    max_string_length=max_string_length,
                    max_payload_size=max_payload_size,
                    _current_depth=_current_depth + 1,
                    _total_size=_total_size,
                )
            )

        else:
            raise MetadataValidationError(
                f"Metadata array '{parent_key}[{i}]' has unsupported type {type(item).__name__}"
            )

        # Check total size
        if _total_size[0] > max_payload_size:
            raise MetadataValidationError(
                f"Metadata exceeds maximum payload size of {max_payload_size}"
            )

    return validated


def sanitize_metadata(metadata: Any) -> dict[str, Any]:
    """Sanitize and validate metadata, returning a safe copy.

    This is a convenience wrapper around validate_metadata that
    catches validation errors and returns an empty dict instead
    of raising.

    Args:
        metadata: The metadata to sanitize

    Returns:
        The validated metadata, or empty dict if validation fails
    """
    try:
        return validate_metadata(metadata)
    except MetadataValidationError:
        return {}
