"""Unit tests for #5202 - SCIM protocol helpers and tokens (utils/scim/protocol.py, utils/scim/tokens.py)."""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from fixtures import scim_env  # pylint: disable=C0413

MODULES = scim_env.load()
protocol = MODULES["utils.scim.protocol"]
tokens = MODULES["utils.scim.tokens"]
graph = MODULES["utils.scim.graph"]


# ---------- filter (AC-3, AC-4) ----------

@pytest.mark.parametrize("text, expected", [
    ('userName eq "Jane@Contoso.com"', ("username", "Jane@Contoso.com")),
    ('displayName eq "[ELITEA] Team X"', ("displayname", "[ELITEA] Team X")),
    ('externalId eq "0f1e-22"', ("externalid", "0f1e-22")),
    ('  USERNAME   EQ  "a b"  ', ("username", "a b")),
    ('userName eq "with \\"quote\\""', ("username", 'with "quote"')),
])
def test_parse_filter_supported(text, expected):
    assert protocol.parse_filter(text) == expected


def test_parse_filter_empty_is_none():
    assert protocol.parse_filter(None) is None
    assert protocol.parse_filter("") is None


@pytest.mark.parametrize("text", [
    'userName co "a"', 'title eq "x"', 'userName eq a', 'userName eq "a" and active eq true',
])
def test_parse_filter_unsupported_is_400(text):
    with pytest.raises(protocol.ScimError) as exc:
        protocol.parse_filter(text)
    assert exc.value.status == 400
    assert exc.value.scim_type == "invalidFilter"


# ---------- patch (AC-6, AC-8, AC-4b) ----------

def test_parse_patch_normalises_entra_ops():
    body = {
        "schemas": [protocol.PATCH_OP],
        "Operations": [
            {"op": "Replace", "path": "active", "value": "False"},
            {"op": "Add", "path": "members", "value": [{"value": "u1"}]},
            {"op": "remove", "path": 'members[value eq "u2"]'},
        ],
    }
    assert protocol.parse_patch(body) == [
        ("replace", "active", "False"),
        ("add", "members", [{"value": "u1"}]),
        ("remove", 'members[value eq "u2"]', None),
    ]


@pytest.mark.parametrize("body", [
    {"Operations": [{"op": "add", "path": "x", "value": 1}]},
    {"schemas": [protocol.PATCH_OP], "Operations": [{"op": "move", "path": "x"}]},
    {"schemas": [protocol.PATCH_OP]},
    {"schemas": [protocol.PATCH_OP], "Operations": "nope"},
])
def test_parse_patch_invalid_is_400(body):
    with pytest.raises(protocol.ScimError) as exc:
        protocol.parse_patch(body)
    assert exc.value.status == 400


@pytest.mark.parametrize("value, expected", [
    (True, True), (False, False), ("True", True), ("False", False), ("false", False), ("TRUE", True),
])
def test_bool_value(value, expected):
    assert protocol.bool_value(value) is expected


def test_bool_value_rejects_garbage():
    with pytest.raises(protocol.ScimError):
        protocol.bool_value("maybe")


def test_member_filter_value():
    assert protocol.member_filter_value('members[value eq "abc-1"]') == "abc-1"
    assert protocol.member_filter_value("members") is None


# ---------- users: email (AC-3) ----------

def test_primary_email_prefers_primary_and_lowercases():
    resource = {"userName": "jdoe@contoso.com", "emails": [
        {"value": "Other@Contoso.com", "type": "home"},
        {"value": "Jane.Doe@Contoso.com", "type": "work", "primary": True},
    ]}
    assert protocol.primary_email(resource) == "jane.doe@contoso.com"


def test_primary_email_falls_back_to_first_then_username():
    assert protocol.primary_email({"emails": [{"value": "A@B.com"}]}) == "a@b.com"
    assert protocol.primary_email({"userName": "Jane@Contoso.com"}) == "jane@contoso.com"
    assert protocol.primary_email({"userName": "no-at-sign"}) is None


# ---------- project names (AC-5) ----------

@pytest.mark.parametrize("group_name, expected", [
    ("Sales Team", "Sales Team"),
    ("  Sales    Team  ", "Sales Team"),
    ("R&D (EU) v1.2_x-y", "R&D (EU) v1.2_x-y"),
    ("Team / 2026", "Team - 2026"),
    ("a\tb\nc", "a b c"),
    ("Ops\x00\x07!!", "Ops"),
    ("Équipe Données", "Équipe Données"),
    ("Rocket 🚀 team", "Rocket - team"),
    ("***", "scim-group"),
    ("", "scim-group"),
    (None, "scim-group"),
    ("project_user_42", "group-project_user_42"),
    ("PROJECT_USER_x", "group-PROJECT_USER_x"),
])
def test_sanitize_project_name(group_name, expected):
    assert protocol.sanitize_project_name(group_name) == expected


def test_sanitize_caps_length():
    assert len(protocol.sanitize_project_name("x" * 500)) == protocol.PROJECT_NAME_MAX


def test_project_name_is_the_sanitized_group_name_only():
    assert protocol.project_name_for("Sales Team") == "Sales Team"
    assert protocol.project_name_for("  Sales / Team ") == "Sales - Team"


# ---------- Graph nesting parser (AC-8) ----------

def test_child_group_ids_from_graph_pages():
    pages = [
        {"value": [{"@odata.type": "#microsoft.graph.group", "id": "b"}], "@odata.nextLink": "next"},
        {"value": [{"@odata.type": "#microsoft.graph.group", "id": "c"}, {"id": "d"}]},
    ]
    assert graph.child_group_ids(pages) == ["b", "c", "d"]


# ---------- errors and lists ----------

def test_error_body():
    error = protocol.ScimError(409, "userName already exists", "uniqueness")
    assert error.body() == {
        "schemas": [protocol.ERROR], "status": "409", "scimType": "uniqueness", "detail": "userName already exists",
    }


def test_list_response():
    assert protocol.list_response([{"id": "1"}], total=5, start_index=3) == {
        "schemas": [protocol.LIST_RESPONSE], "totalResults": 5, "startIndex": 3, "itemsPerPage": 1,
        "Resources": [{"id": "1"}],
    }


@pytest.mark.parametrize("args, expected", [
    ({}, (1, 100)), ({"startIndex": "0", "count": "500"}, (1, 200)), ({"startIndex": "3", "count": "0"}, (3, 0)),
])
def test_page_args(args, expected):
    assert protocol.page_args(args) == expected


def test_page_args_non_numeric_is_400():
    with pytest.raises(protocol.ScimError):
        protocol.page_args({"count": "x"})


# ---------- tokens (AC-1, AC-2) ----------

def test_generate_token_is_prefixed_hashed_and_random():
    token, token_hash, last4 = tokens.generate()
    assert token.startswith(tokens.PREFIX) and len(token) > 40
    assert token_hash == tokens.hash_token(token) and token not in token_hash
    assert last4 == token[-4:]
    assert tokens.generate()[0] != token


def _verifier(valid="scim1.good"):
    return tokens.make_verifier(
        verify=lambda token: token == valid, service_user_id=lambda: 7, path_prefix="/api/v2/admin/scim/",
    )


def test_verifier_accepts_valid_token_on_scim_path():
    verdict = _verifier()("scim1.good", {"PATH_INFO": "/api/v2/admin/scim/administration/Users"})
    assert verdict == {"ok": True, "user_id": 7}


def test_verifier_refuses_invalid_token():
    verdict = _verifier()("scim1.bad", {"PATH_INFO": "/api/v2/admin/scim/administration/Users"})
    assert verdict["ok"] is False and verdict["status"] == 401


def test_verifier_refuses_scim_token_outside_scim_api():
    verdict = _verifier()("scim1.good", {"PATH_INFO": "/api/v2/admin/users/administration/1"})
    assert verdict["ok"] is False and verdict["status"] == 403


def test_verifier_fails_closed_without_service_user():
    verifier = tokens.make_verifier(lambda t: True, lambda: None, "/api/v2/admin/scim/")
    verdict = verifier("scim1.good", {"PATH_INFO": "/api/v2/admin/scim/administration/Users"})
    assert verdict["ok"] is False and verdict["status"] == 503
