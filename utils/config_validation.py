"""Validation helpers for schema-driven administration settings."""

from jsonschema import Draft202012Validator


def _error_message(error):
    """Return a useful validation error without echoing the rejected value."""
    path = ".".join(str(part) for part in error.absolute_path)
    prefix = f"{path}: " if path else ""

    if error.validator == "required":
        missing = [
            name for name in error.validator_value
            if not isinstance(error.instance, dict) or name not in error.instance
        ]
        name = missing[0] if missing else "value"
        return f"{prefix}missing required property '{name}'"
    if error.validator == "type":
        expected = error.validator_value
        if isinstance(expected, list):
            expected = " or ".join(expected)
        return f"{prefix}expected {expected}"
    if error.validator == "enum":
        allowed = ", ".join(str(value) for value in error.validator_value)
        return f"{prefix}must be one of: {allowed}"
    if error.validator == "pattern":
        return f"{prefix}does not match the required format"
    if error.validator == "minLength":
        return f"{prefix}must not be empty"

    return f"{prefix}is invalid ({error.validator})"


def validate_config_value(field_schema, value, *, max_errors=10):
    """Validate a field value against its optional ``value_schema`` contract.

    Admin schemas predate full JSON Schema support and contain UI/runtime keys
    alongside type information. ``value_schema`` keeps validation explicit and
    prevents existing fields from acquiring stricter behavior accidentally.
    """
    value_schema = field_schema.get("value_schema")
    if not value_schema:
        return []

    Draft202012Validator.check_schema(value_schema)
    validator = Draft202012Validator(value_schema)
    errors = sorted(
        validator.iter_errors(value),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    return [
        {
            "path": ".".join(str(part) for part in error.absolute_path),
            "message": _error_message(error),
        }
        for error in errors[:max_errors]
    ]
