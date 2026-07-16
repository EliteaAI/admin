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
