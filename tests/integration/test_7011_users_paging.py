"""EL-7011 US-04: GET project users supports limit, offset and query (R1.1-R1.3, R2.1-R2.3)."""
import importlib.util
import sys
import types

import pytest

VIEW = "configuration.users.users.view"
PROJECT_ID = 3
SYSTEM_USER_ID = 900
OUTSIDER_ID = 901


class FakeAuth(types.ModuleType):
    def __init__(self, users):
        super().__init__("tools.auth")
        self.users = users
        self.granted = {VIEW}
        self.decorators = types.SimpleNamespace(check_api=self._check_api)

    def _check_api(self, config):
        needed = config["permissions"]

        def wrap(func):
            def checked(*args, **kwargs):
                if not set(needed) <= self.granted:
                    return {"msg": "forbidden"}, 403
                return func(*args, **kwargs)

            checked.needed = needed
            return checked

        return wrap

    def list_users(self, user_ids=None):
        return [dict(u) for u in self.users if user_ids is None or u["id"] in user_ids]


def make_user(user_id, name, email=None):
    return {"id": user_id, "name": name, "email": email or f"u{user_id}@corp.test", "last_login": None}


def default_users():
    # 45 members; 7 is coprime with 45, so names are unique and differ from id order.
    return [make_user(i, f"User {(i * 7) % 45:02d}") for i in range(1, 46)]


class Env:
    def __init__(self, module, users, social_calls):
        self.module = module
        self.users = users
        self.social_calls = social_calls
        self.api = module.API()
        self.api.module = self._plugin(users, social_calls)

    @staticmethod
    def _plugin(users, social_calls):
        members = {u["id"]: ["viewer"] for u in users}

        def get_users_roles_in_project(project_id, filter_system_user=False):
            roles = dict(members)
            if not filter_system_user:
                roles[SYSTEM_USER_ID] = ["system"]
            return roles

        def social_get_users(ids):
            social_calls.append(set(ids))
            return [{"user_id": i, "avatar": f"a{i}"} for i in ids]

        rpc = types.SimpleNamespace(call=types.SimpleNamespace(social_get_users=social_get_users))
        return types.SimpleNamespace(
            get_users_roles_in_project=get_users_roles_in_project,
            context=types.SimpleNamespace(rpc_manager=rpc),
        )

    def get(self, **args):
        self.module.request = types.SimpleNamespace(args={k: str(v) for k, v in args.items()})
        return self.api.get(project_id=PROJECT_ID)


@pytest.fixture
def make_env(plugin_root, monkeypatch):
    def build(members=None):
        members = default_users() if members is None else members
        # Non-members that a leaky handler would return: the system user and an outsider.
        platform_users = members + [
            make_user(SYSTEM_USER_ID, "project_P_system"),
            make_user(OUTSIDER_ID, "Outsider Zed"),
        ]
        fake_auth = FakeAuth(platform_users)
        tools = types.ModuleType("tools")
        tools.auth = fake_auth
        tools.api_tools = types.SimpleNamespace(
            APIModeHandler=object, APIBase=object, endpoint_metrics=lambda f: f
        )
        tools.register_openapi = lambda **k: (lambda f: f)
        monkeypatch.setitem(sys.modules, "tools", tools)
        monkeypatch.setitem(sys.modules, "tools.auth", fake_auth)
        monkeypatch.setitem(sys.modules, "flask", types.SimpleNamespace(request=None))
        for name in ("pydantic", "pydantic.v1"):
            monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(ValidationError=ValueError))
        pylon_tools = types.ModuleType("pylon.core.tools")
        pylon_tools.log = None
        for name in ("pylon", "pylon.core"):
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
        monkeypatch.setitem(sys.modules, "pylon.core.tools", pylon_tools)

        pd_module = types.ModuleType("fakeadmin.models.pd.user_input_field")
        pd_module.UserInputFieldPD = object
        utils = types.ModuleType("fakeadmin.utils")
        utils.validate_role_assignment = lambda roles: (True, [])
        utils.get_role_validation_error = lambda roles: ({}, 400)
        for name in ("fakeadmin", "fakeadmin.api", "fakeadmin.api.v2", "fakeadmin.models", "fakeadmin.models.pd"):
            package = types.ModuleType(name)
            package.__path__ = []
            monkeypatch.setitem(sys.modules, name, package)
        monkeypatch.setitem(sys.modules, "fakeadmin.models.pd.user_input_field", pd_module)
        monkeypatch.setitem(sys.modules, "fakeadmin.utils", utils)

        spec = importlib.util.spec_from_file_location(
            "fakeadmin.api.v2.users", plugin_root / "api" / "v2" / "users.py"
        )
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, "fakeadmin.api.v2.users", module)
        spec.loader.exec_module(module)
        env = Env(module, members, [])
        env.auth = fake_auth
        return env

    return build


@pytest.fixture
def env(make_env):
    return make_env()


def ids(result):
    return [row["id"] for row in result[0]["rows"]]


def ordered_ids(users):
    return [u["id"] for u in sorted(users, key=lambda u: (u["name"], u["id"]))]


@pytest.mark.parametrize(
    "offset,count",
    [
        pytest.param(20, 20, id="TC-US04-01 second page"),
        pytest.param(100, 0, id="TC-US04-02 offset past the end"),
        pytest.param(40, 5, id="TC-US04-03 last page"),
    ],
)
def test_el7011_r1_1_r1_2_page_has_at_most_limit_rows_and_full_total(env, offset, count):
    body, status = env.get(limit=20, offset=offset)

    assert status == 200
    assert body["total"] == 45
    assert ids((body, status)) == ordered_ids(env.users)[offset:offset + 20]
    assert len(body["rows"]) == count


def test_el7011_r1_1_avatars_load_for_page_ids_only(env):
    result = env.get(limit=20, offset=0)

    assert result[1] == 200
    assert env.social_calls == [set(ids(result))]
    assert len(env.social_calls[0]) == 20
    assert all(row["avatar"] == f"a{row['id']}" for row in result[0]["rows"])


def test_el7011_r1_1_same_name_keeps_stable_order_across_pages(make_env):
    users = default_users()
    users[6]["name"] = users[8]["name"] = "Alex"  # ids 7 and 9
    env = make_env(users)
    k = ordered_ids(users).index(7)

    first = env.get(limit=1, offset=k)
    second = env.get(limit=1, offset=k + 1)

    assert ids(first) == [7]
    assert ids(second) == [9]


def test_el7011_r2_1_query_matches_name_or_email_ignoring_case(make_env):
    users = default_users()
    users[0] = make_user(1, "Anna Smith", "asmith@example.com")
    users[1] = make_user(2, "Bob", "anna.b@example.com")
    env = make_env(users)

    body, status = env.get(limit=20, offset=0, query="ANNA")

    assert status == 200
    assert body["total"] == 2
    assert ids((body, status)) == [1, 2]


def test_el7011_r2_2_query_without_match_returns_200_and_empty_list(env):
    assert env.get(limit=20, offset=0, query="zzzz-no-user") == ({"total": 0, "rows": []}, 200)


@pytest.mark.parametrize("query", ["", "%20%20", "  "])
def test_el7011_r2_1_blank_query_is_no_search(env, query):
    assert env.get(limit=20, offset=0, query=query) == env.get(limit=20, offset=0)
    body, _ = env.get(limit=20, offset=0, query=query)
    assert body["total"] == 45 and len(body["rows"]) == 20


def test_el7011_r2_1_r1_2_search_and_paging_total_counts_matches(make_env):
    users = [make_user(i, f"Jane {i:02d}") for i in range(1, 31)]
    users += [make_user(i, f"Bob {i:02d}") for i in range(31, 46)]
    env = make_env(users)
    matches = ordered_ids(users[:30])

    body, status = env.get(limit=10, offset=10, query="an")

    assert status == 200
    assert body["total"] == 30
    assert ids((body, status)) == matches[10:20]


@pytest.mark.parametrize("limit,count", [(1, 1), (100, 45)])
def test_el7011_r1_3_limit_bounds_are_accepted(env, limit, count):
    body, status = env.get(limit=limit, offset=0)

    assert status == 200
    assert len(body["rows"]) == count


@pytest.mark.parametrize("limit", ["0", "101", "abc", "1.5", "-5"])
def test_el7011_r1_3_bad_limit_returns_400_naming_limit(env, limit):
    assert env.get(limit=limit, offset=0) == (
        {"msg": "limit must be a whole number from 1 to 100"}, 400)


@pytest.mark.parametrize("offset", ["-1", "x", "2.5"])
def test_el7011_r1_3_bad_offset_returns_400_naming_offset(env, offset):
    assert env.get(limit=20, offset=offset) == (
        {"msg": "offset must be a whole number, 0 or more"}, 400)


def test_el7011_r2_3_system_user_and_outsiders_never_listed(env):
    paged = env.get(limit=100, offset=0)
    full = env.get()

    assert paged[0]["total"] == 45
    for result in (paged, full):
        assert {SYSTEM_USER_ID, OUTSIDER_ID}.isdisjoint(ids(result))
        assert set(ids(result)) == {u["id"] for u in env.users}


@pytest.mark.parametrize("query", ["project_P_system", "Outsider"])
def test_el7011_r2_3_query_cannot_reach_non_members(env, query):
    assert env.get(limit=20, offset=0, query=query) == ({"total": 0, "rows": []}, 200)


def test_el7011_r2_3_view_permission_is_required(env):
    assert env.api.get.needed == [VIEW]
    env.auth.granted = set()

    body, status = env.get(limit=20, offset=0)

    assert status == 403
    assert "rows" not in body
