"""Unit tests for #7722 - safe backup takes a token only where it starts a word."""
import importlib.util
import json
import pathlib
import sys
import types

import pytest


UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"


def _load_project_backup():
    """Import utils/project_backup.py without a running pylon"""
    if "pylon.core.tools" not in sys.modules:
        tools = types.ModuleType("pylon.core.tools")
        tools.log = types.SimpleNamespace(
            info=lambda *a, **k: None, warning=lambda *a, **k: None,
            error=lambda *a, **k: None, exception=lambda *a, **k: None,
        )
        sys.modules.setdefault("pylon", types.ModuleType("pylon"))
        sys.modules.setdefault("pylon.core", types.ModuleType("pylon.core"))
        sys.modules["pylon.core.tools"] = tools
    #
    spec = importlib.util.spec_from_file_location(
        "_admin_project_backup_7722", UTILS_PATH / "project_backup.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pb = _load_project_backup()

INSTRUCTIONS = (
    "# Backup check skill\n"
    "Follow task-management-guidelines and the risk-assessment-framework.\n"
    "Book rooms with the desk-reservation-system and stream park_live_events.\n"
)

TOKENS = [
    "sk-proj-abcdefghijklmnop1234",
    "sk-abcdefghijklmnopqrstuvwx",
    "ghp_ABCDEFabcdef0123456789ABCDEFabcdef",
    "github_pat_11ABCDEFG0abcdefghij_klmnopqrstuvwxyz0123456789",
    "glpat-abcdefghij0123456789",
    "xoxb-1234567890-0987654321-AbCdEfGhIjKl",
    "sk_live_abcdefghijklmnop0123",
    "rk_live_abcdefghijklmnop0123",
    "AKIAABCDEFGHIJKLMNOP",
    "ASIAABCDEFGHIJKLMNOP",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
    "rk_live_",
    "sk_live_",
]


@pytest.mark.parametrize("text", [
    "task-management-guidelines",
    "risk-assessment-framework-v2",
    "desk-reservation-system",
    "park_live_events",
    "mask_live_values",
    "Ask-questions-before-answering-users",
    "dask-learn-pipeline-template-guide",
    "ask_live_",
    "task-Kubernetes-deployment-guide",
    "task-2024-roadmap-planning-notes",
    "Sync the desk_live_status_board_feed",
    "line1\\ntask-management-guidelines",
    "%20task-management-guidelines",
    "mask-pii-in-utf8-logs-before-upload",
    "task-oauth2-setup-guidelines",
    "task-web3-integration-guide",
    "task-gpt4o-routing-notes",
    "desk-booking-api-v1beta",
    "Follow the task-step1-instructions-file",
    "task-20241125-review-notes",
    "park_live_stream1",
    "C:\\Docs\\ask-questions-before-answering.md",
    INSTRUCTIONS,
])
def test_words_containing_a_token_prefix_are_not_secrets(text):
    assert not pb.looks_like_secret_value(text)


@pytest.mark.parametrize("token", TOKENS)
def test_token_in_prose_is_a_secret(token):
    assert pb.looks_like_secret_value("Call the API with {} then summarise.".format(token))


@pytest.mark.parametrize("template", [
    "{}",
    "key={}",
    "Authorization: Bearer {}",
    '{{"api": "{}"}}',
    "https://example.com/hook?token%3D{}&x=1",
    "MY_TOKEN_{}",
    "line1\\n{}",
    "col\\t{}",
    "quote\\u0022{}",
])
def test_token_after_a_separator_or_escape_is_a_secret(template):
    assert pb.looks_like_secret_value(template.format("ghp_ABCDEFabcdef0123456789ABCDEFabcdef"))


ESCAPES_AND_ENCODINGS = [
    "line1\\n{}", "col\\t{}", "v\\v{}", "quote\\u0022{}", "quote\\U00000022{}", "hex\\x22{}",
    "octal\\042{}", "octal\\42{}", "nul\\0{}", "url%3D{}", "url%253D{}", "url%u0022{}", "qp=3D{}",
    "\\x1b[32m{}", "qp=3d{}", "&quot{}", "url%252522{}", "hex\\x9{}", "hex\\X22{}", "glued{}", "9{}",
]


@pytest.mark.parametrize("template", ESCAPES_AND_ENCODINGS)
@pytest.mark.parametrize("token", ["sk-proj-abcdefghijklmnop1234", "sk_live_abcdefghijklmnop0123"])
def test_sk_token_after_an_escape_or_encoding_is_a_secret(template, token):
    assert pb.looks_like_secret_value(template.format(token))


@pytest.mark.parametrize("text", [
    "toxoxb-integration",
    "eghp_notatoken",
    "awsKeyAKIAABCDEFGHIJKLMNOP",
    "ideyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
    "hex\\x22glpat-abcdefghij0123456789",
    "tosk-aBcDeFgHiJkLmNoPqRsT",
    "\\nsk-AB12-CD34-EF56-GH78",
    "\\nsk-Abcdefghijklmnopqrstuvwx",
    "\\nsk_live_12345",
    "\\nsk-ant-api03-2X4b_Rm7JusI-f3_qq3_YpGh5C_kPZgxv__seB-ZKR7-XgHY7_lMgAew_MOlm0gIbW0jPGyBqvkE3PaOGSexfYz-TFzh",
])
def test_distinctive_token_glued_to_text_is_a_secret(text):
    assert pb.looks_like_secret_value(text)


def test_private_key_block_is_a_secret():
    assert pb.looks_like_secret_value("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----")


def test_text_column_keeps_instructions_and_counts_no_hit():
    redactor = pb._Redactor([("id", "integer"), ("instructions", "text")])  # pylint: disable=W0212
    row = redactor.apply({"id": 1, "instructions": INSTRUCTIONS})
    assert row["instructions"] == INSTRUCTIONS
    assert redactor.hits == 0


def test_text_column_with_a_token_redacts_the_whole_value_with_its_neighbours():
    redactor = pb._Redactor([("id", "integer"), ("notes", "text")])  # pylint: disable=W0212
    value = "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCY"
    row = redactor.apply({"id": 1, "notes": value})
    assert row["notes"] == pb.REDACTED
    assert redactor.hits == 1


def test_json_column_keeps_prose_and_redacts_the_string_with_a_token():
    redactor = pb._Redactor([("id", "integer"), ("data", "jsonb")])  # pylint: disable=W0212
    data = {"instructions": INSTRUCTIONS, "example": "git clone https://oauth2:glpat-abcdefghij0123456789@x/y.git"}
    row = redactor.apply({"id": 1, "data": json.dumps(data)})
    assert json.loads(row["data"]) == {"instructions": INSTRUCTIONS, "example": pb.REDACTED}
    assert redactor.hits == 1


def test_unparsable_json_text_with_an_escaped_token_is_redacted():
    value = '{"a": "line1\\nghp_ABCDEFabcdef0123456789ABCDEFabcdef"'
    assert pb._Redactor._scrub_json(value) == pb.REDACTED  # pylint: disable=W0212
