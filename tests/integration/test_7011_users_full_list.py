"""Full list users endpoint returns all project members when limit is not set (EL-7011).

Tests for:
- TC-US04-10 (R1.4, R2.3): No limit returns every project user with today's fields
- TC-US04-11 (R1.4): An offset without a limit is ignored
- TC-US04-12 (R1.4): The full list still returns when the avatar service is down
"""
import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # importlib import mode adds no sibling path

import test_7011_users_paging as paging  # sibling module with the shared stubs

# pytest registers a fixture under its own name, so these re-exports supply `env` and `make_env`.
env = paging.env
make_env = paging.make_env


def test_no_limit_returns_all_project_users(env):
    """TC-US04-10 (R1.4, R2.3): No limit returns every project user with today's fields.

    When the request has no limit parameter, the endpoint returns all project members
    (45 users) with the same fields as before: id, name, email, roles, last_login, avatar.
    """
    result, status = env.get()

    assert status == 200
    assert result["total"] == 45, "Total should be 45 members"
    assert len(result["rows"]) == 45, "Should return all 45 members"

    # Verify that each row has the expected fields
    for row in result["rows"]:
        assert "id" in row
        assert "name" in row
        assert "email" in row
        assert "roles" in row
        assert "avatar" in row


def test_full_list_excludes_system_user_and_outsider_and_keeps_last_login(make_env):
    """R2.3, R1.4: The full list has no system user and no outsider; last_login stays ISO text."""
    members = paging.default_users()
    members[0]["last_login"] = datetime.datetime(2026, 10, 1, 12, 30, 45, 999)
    env = make_env(members)

    result, status = env.get()

    assert status == 200
    assert {paging.SYSTEM_USER_ID, paging.OUTSIDER_ID}.isdisjoint(paging.ids((result, status)))
    assert set(paging.ids((result, status))) == {u["id"] for u in members}
    by_id = {row["id"]: row for row in result["rows"]}
    assert by_id[members[0]["id"]]["last_login"] == "2026-10-01T12:30:45"
    assert by_id[members[1]["id"]]["last_login"] is None


def test_offset_without_limit_is_ignored(env):
    """TC-US04-11 (R1.4): An offset without a limit is ignored.

    When the request has an offset but no limit, the offset is ignored and
    all project members are returned.
    """
    result, status = env.get(offset=10)

    assert status == 200
    assert result["total"] == 45, "Total should be 45 members"
    assert len(result["rows"]) == 45, "Should return all 45 members, not starting at offset 10"


def test_full_list_without_avatar_service(env):
    """TC-US04-12 (R1.4): The full list still returns when the avatar service is down.

    When the avatar service (social_get_users) fails, the endpoint still returns
    all users but with no avatar data.
    """
    # Make social_get_users raise an error
    def failing_social_get_users(ids):
        raise KeyError("social service not available")

    env.api.module.context.rpc_manager.call.social_get_users = failing_social_get_users

    result, status = env.get()

    assert status == 200
    assert result["total"] == 45, "Total should be 45 members"
    assert len(result["rows"]) == 45, "Should return all 45 members"

    # Verify that avatars are None when service fails
    for row in result["rows"]:
        assert row.get("avatar") is None
