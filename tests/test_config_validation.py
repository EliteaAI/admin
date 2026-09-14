"""Tests for schema-driven configuration validation."""

import importlib.util
from pathlib import Path


_MODULE_PATH = Path(__file__).parents[1] / "utils" / "config_validation.py"
_SPEC = importlib.util.spec_from_file_location("config_validation", _MODULE_PATH)
config_validation = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(config_validation)


MCP_FIELD_SCHEMA = {
    "value_schema": {
        "type": "object",
        "additionalProperties": {
            "type": "object",
            "required": ["type"],
            "properties": {
                "type": {"enum": ["http", "stdio"]},
                "url": {"type": "string", "pattern": "^https?://"},
                "command": {"type": "string", "minLength": 1},
            },
            "allOf": [
                {
                    "if": {"properties": {"type": {"const": "http"}}},
                    "then": {"required": ["url"]},
                },
                {
                    "if": {"properties": {"type": {"const": "stdio"}}},
                    "then": {"required": ["command"]},
                },
            ],
        },
    },
}


def test_field_without_value_schema_remains_unvalidated():
    assert config_validation.validate_config_value({"type": "object"}, "anything") == []


def test_valid_http_and_stdio_servers_are_accepted():
    value = {
        "Remote": {"type": "http", "url": "https://mcp.example.test/api"},
        "Local": {"type": "stdio", "command": "npx"},
    }
    assert config_validation.validate_config_value(MCP_FIELD_SCHEMA, value) == []


def test_missing_transport_setting_returns_server_scoped_error():
    errors = config_validation.validate_config_value(
        MCP_FIELD_SCHEMA,
        {"Remote": {"type": "http"}},
    )
    assert errors == [{
        "path": "Remote",
        "message": "Remote: missing required property 'url'",
    }]


def test_rejected_value_is_not_reflected_in_error_message():
    secret = "secret-value-that-must-not-be-logged"
    errors = config_validation.validate_config_value(
        MCP_FIELD_SCHEMA,
        {"Remote": {"type": secret}},
    )
    assert errors == [{
        "path": "Remote.type",
        "message": "Remote.type: must be one of: http, stdio",
    }]
    assert secret not in str(errors)


CRON_FIELD_SCHEMA = {"type": "string", "format": "cron", "default": "* * * * *"}


def test_cron_format_accepts_standard_expressions():
    for value in ("* * * * *", "*/15 * * * *", "9 * * * *", "0 2 * * SUN"):
        assert config_validation.validate_config_value(CRON_FIELD_SCHEMA, value) == [], value


def test_cron_format_rejects_malformed_expressions():
    for value in ("9 *", "not a cron", "", None, 5):
        errors = config_validation.validate_config_value(CRON_FIELD_SCHEMA, value)
        assert errors == [{
            "path": "",
            "message": "must be a valid cron expression",
        }], value


def test_cron_is_checked_without_a_value_schema():
    assert "value_schema" not in CRON_FIELD_SCHEMA
    assert config_validation.validate_config_value(CRON_FIELD_SCHEMA, "9 *")


def test_cron_error_does_not_echo_the_rejected_value():
    errors = config_validation.validate_config_value(CRON_FIELD_SCHEMA, "s3cr3t-ish")
    assert "s3cr3t-ish" not in errors[0]["message"]


def test_cron_and_value_schema_errors_are_reported_together():
    field = {**CRON_FIELD_SCHEMA, "value_schema": {"type": "integer"}}
    errors = config_validation.validate_config_value(field, "9 *")
    messages = [error["message"] for error in errors]
    assert "must be a valid cron expression" in messages
    assert any("expected integer" in message for message in messages)


def test_fields_without_the_cron_format_are_unaffected():
    assert config_validation.validate_config_value({"type": "string"}, "9 *") == []


def test_effective_value_reports_the_default_for_an_unusable_cron():
    assert config_validation.effective_config_value(CRON_FIELD_SCHEMA, "9 *") == "* * * * *"
    assert config_validation.effective_config_value(CRON_FIELD_SCHEMA, None) == "* * * * *"


def test_effective_value_passes_a_usable_cron_through():
    assert config_validation.effective_config_value(
        CRON_FIELD_SCHEMA, "*/15 * * * *"
    ) == "*/15 * * * *"


def test_effective_value_leaves_other_fields_alone():
    assert config_validation.effective_config_value({"type": "string"}, "9 *") == "9 *"
    assert config_validation.effective_config_value(
        {"type": "string", "default": "x"}, None
    ) == "x"


BOOL_FIELD_SCHEMA = {"type": "boolean", "strict_type": True, "default": True}
LOOSE_BOOL_SCHEMA = {"type": "boolean", "default": True}


def test_effective_value_reports_the_default_for_a_non_boolean():
    for stored in (0, 1, "false", "true", ""):
        assert config_validation.effective_config_value(
            BOOL_FIELD_SCHEMA, stored
        ) is True, stored


def test_effective_value_passes_real_booleans_through():
    assert config_validation.effective_config_value(BOOL_FIELD_SCHEMA, False) is False
    assert config_validation.effective_config_value(BOOL_FIELD_SCHEMA, True) is True


def test_non_boolean_fields_are_unaffected_by_the_boolean_check():
    assert config_validation.effective_config_value({"type": "string"}, 0) == 0


def test_a_boolean_without_strict_type_is_left_alone():
    assert config_validation.effective_config_value(LOOSE_BOOL_SCHEMA, 0) == 0
    assert config_validation.effective_config_value(LOOSE_BOOL_SCHEMA, "false") == "false"
    assert not config_validation.stored_value_is_unusable(LOOSE_BOOL_SCHEMA, 0)


def test_an_unusable_stored_value_never_silences_a_save():
    assert config_validation.stored_value_is_unusable(BOOL_FIELD_SCHEMA, 0)
    assert config_validation.stored_value_is_unusable(CRON_FIELD_SCHEMA, "9 *")
    assert not config_validation.stored_value_is_unusable(CRON_FIELD_SCHEMA, "* * * * *")
