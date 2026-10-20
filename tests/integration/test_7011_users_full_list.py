"""Full list users endpoint returns all project members when limit is not set (EL-7011).

Tests for:
- TC-US04-10: No limit returns every project user with today's fields
- TC-US04-11: An offset without a limit is ignored
- TC-US04-12: The full list still returns when the avatar service is down
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # importlib import mode adds no sibling path

from test_7011_users_paging import env, make_env  # noqa: E402,F401  (shared stubs and fixtures)


def test_no_limit_returns_all_project_users(env):
    """TC-US04-10: No limit returns every project user with today's fields.

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


def test_offset_without_limit_is_ignored(env):
    """TC-US04-11: An offset without a limit is ignored.

    When the request has an offset but no limit, the offset is ignored and
    all project members are returned.
    """
    result, status = env.get(offset=10)

    assert status == 200
    assert result["total"] == 45, "Total should be 45 members"
    assert len(result["rows"]) == 45, "Should return all 45 members, not starting at offset 10"


def test_full_list_without_avatar_service(env):
    """TC-US04-12: The full list still returns when the avatar service is down.

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
