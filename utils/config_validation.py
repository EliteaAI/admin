"""Validation helpers for schema-driven administration settings."""

import re
from re import _constants as sre_constants
from re import _parser as sre_parser

from croniter import croniter
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


def _cron_errors(field_schema, value):
    """Reject cron expressions the scheduler would silently refuse to apply."""
    if field_schema.get("format") != "cron":
        return []
    if isinstance(value, str) and croniter.is_valid(value):
        return []
    return [{"path": "", "message": "must be a valid cron expression"}]


_REPEAT_OPCODES = (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT)


def _subpatterns(value):
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, sre_parser.SubPattern):
            yield item
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


def _has_nested_quantifier(parsed, inside_unbounded=False):
    """True for ``(a+)+``-style shapes: a repeat inside an unbounded repeat backtracks
    exponentially on a near-miss, and an allow pattern runs on every detection."""
    for opcode, argument in parsed:
        if opcode in _REPEAT_OPCODES:
            _, max_count, body = argument
            if inside_unbounded and max_count > 1:
                return True
            if _has_nested_quantifier(body, inside_unbounded or max_count == sre_constants.MAXREPEAT):
                return True
            continue
        if any(_has_nested_quantifier(child, inside_unbounded) for child in _subpatterns(argument)):
            return True
    return False


def _regex_list_errors(field_schema, value):
    """Reject list entries the consumer would fail to compile; names the index, never the text."""
    if field_schema.get("format") != "regex_list" or not isinstance(value, list):
        return []
    errors = []
    for index, pattern in enumerate(value):
        try:
            re.compile(pattern)
            nested = _has_nested_quantifier(sre_parser.parse(pattern))
        # compile() can also raise OverflowError (e.g. ``a{4294967296}``) and
        # RecursionError (deeply nested groups); both must stay a 400, not a 500.
        except (re.error, TypeError, ValueError, OverflowError, RecursionError):
            errors.append({"path": str(index), "message": f"[{index}]: invalid regex"})
            continue
        if nested:
            errors.append({"path": str(index), "message": f"[{index}]: nested quantifier is not allowed"})
    return errors


def _boolean_errors(field_schema, value):
    """Reject a boolean field holding something that is not one, when it opts in."""
    if not field_schema.get("strict_type"):
        return []
    if field_schema.get("type") != "boolean":
        return []
    if isinstance(value, bool):
        return []
    return [{"path": "", "message": "must be true or false"}]


def stored_value_is_unusable(field_schema, value):
    """Whether something is stored and its consumer would reject it."""
    if value is None:
        return False
    return bool(
        _cron_errors(field_schema, value) or _boolean_errors(field_schema, value)
    )


def effective_config_value(field_schema, value):
    """The value the platform actually runs, given what is stored."""
    default = field_schema.get("default")
    if value is None:
        return default
    if _cron_errors(field_schema, value) or _boolean_errors(field_schema, value):
        if default is not None and not stored_value_is_unusable(
                field_schema, default,
        ):
            return default
    return value


def validate_config_value(field_schema, value, *, max_errors=10):
    """Validate a field value against its optional ``value_schema`` contract.

    Admin schemas predate full JSON Schema support and contain UI/runtime keys
    alongside type information. ``value_schema`` keeps validation explicit and
    prevents existing fields from acquiring stricter behavior accidentally.
    """
    errors = _cron_errors(field_schema, value) + _regex_list_errors(field_schema, value)

    value_schema = field_schema.get("value_schema")
    if not value_schema:
        return errors[:max_errors]

    Draft202012Validator.check_schema(value_schema)
    validator = Draft202012Validator(value_schema)
    schema_errors = sorted(
        validator.iter_errors(value),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    errors.extend(
        {
            "path": ".".join(str(part) for part in error.absolute_path),
            "message": _error_message(error),
        }
        for error in schema_errors
    )
    return errors[:max_errors]
