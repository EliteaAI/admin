"""Integration tests for #5202 (iteration 3) - every SCIM group is linked to an ELITEA project by name.

utils/scim/service.py (Users, Groups, tokens), utils/scim/projects.py (project lifecycle, membership sync,
nesting) and utils/scim/guards.py on SQLite; the platform is the in-memory FakePlatform.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from fixtures import scim_env  # pylint: disable=C0413

MODULES = scim_env.load()
protocol = MODULES["utils.scim.protocol"]
service_module = MODULES["utils.scim.service"]
projects_module = MODULES["utils.scim.projects"]
guards_module = MODULES["utils.scim.guards"]

EXISTING = {"id": 5, "email": "jane@contoso.com"}


class Env:
    def __init__(self, tmp_path):
        self.platform = scim_env.FakePlatform(users=[EXISTING], projects=[{"id": 1, "name": "Taken"}])
        self.get_session = scim_env.session_factory(MODULES["Base"], tmp_path)
        self.changed = []
        self.sync = projects_module.ProjectSync(self.get_session, self.platform)
        self.svc = service_module.ScimService(
            self.get_session, self.platform,
            on_group_changed=self.changed.append, on_user_changed=self.changed.append,
        )
        self.guards = guards_module.Guards(self.get_session)

    def run(self):
        """ What the background worker does after SCIM writes: create projects, then sync memberships """
        self.sync.sync_all()

    def project_of(self, group_id):
        return self.svc.group_summary(group_id)["project_id"]

    def members(self, group_id):
        return self.platform.members.get(self.project_of(group_id), {})


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def user_body(email, external_id=None, active=True):
    return {
        "schemas": [protocol.USER], "externalId": external_id or f"oid-{email}", "userName": email,
        "active": active, "displayName": email.split("@")[0],
        "emails": [{"value": email, "type": "work", "primary": True}],
    }


def group_body(name, members=(), external_id=None):
    return {"schemas": [protocol.GROUP], "displayName": name, "externalId": external_id or f"gid-{name}",
            "members": [{"value": m} for m in members]}


def patch(*operations):
    return {"schemas": [protocol.PATCH_OP],
            "Operations": [dict(zip(("op", "path", "value"), op)) for op in operations]}


def users(env, *emails):
    return [env.svc.create_user(user_body(e)) for e in emails]


# ---------- tokens (AC-1, AC-2) ----------

def test_token_issue_verify_revoke(env):
    issued = env.svc.create_token("entra prod", created_by=1)
    assert issued["token"].startswith("scim1.")
    listed = env.svc.list_tokens()
    assert listed[0]["last4"] == issued["token"][-4:] and "token" not in listed[0]
    assert env.svc.verify_token(issued["token"]) is True
    assert env.svc.list_tokens()[0]["last_used_at"] is not None
    assert env.svc.verify_token("scim1.wrong") is False
    env.svc.revoke_token(issued["id"])
    assert env.svc.verify_token(issued["token"]) is False


def test_rotate_revokes_old_and_issues_new(env):
    old = env.svc.create_token("t", created_by=1)
    new = env.svc.rotate_token(old["id"], created_by=1)
    assert env.svc.verify_token(old["token"]) is False
    assert env.svc.verify_token(new["token"]) is True


# ---------- users (AC-3) ----------

def test_create_user_links_existing_account_without_creating(env):
    created = env.svc.create_user(user_body("Jane@Contoso.com"))
    assert created["userName"] == "Jane@Contoso.com" and created["meta"]["resourceType"] == "User"
    assert env.svc.user_link(created["id"]) == 5
    assert env.platform.created_users == []


def test_create_unknown_user_creates_no_account(env):
    created = env.svc.create_user(user_body("new@contoso.com"))
    assert env.svc.user_link(created["id"]) is None
    assert env.platform.created_users == []


def test_create_user_twice_is_409(env):
    env.svc.create_user(user_body("jane@contoso.com"))
    with pytest.raises(protocol.ScimError) as exc:
        env.svc.create_user(user_body("jane@contoso.com"))
    assert exc.value.status == 409 and exc.value.scim_type == "uniqueness"


def test_filter_users_by_username_case_insensitive(env):
    created = env.svc.create_user(user_body("jane@contoso.com"))
    found = env.svc.list_users('userName eq "JANE@contoso.com"')
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == created["id"]


def test_unknown_user_is_404(env):
    with pytest.raises(protocol.ScimError) as exc:
        env.svc.get_user("missing")
    assert exc.value.status == 404


# ---------- groups → projects (AC-4, AC-5, AC-6) ----------

def test_any_group_name_is_accepted_and_gets_a_project(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Finance", members=[jane["id"]]))
    assert env.svc.group_summary(group["id"])["status"] == "pending"
    env.run()
    summary = env.svc.group_summary(group["id"])
    assert summary["status"] == "active" and summary["project_id"]
    assert env.platform.projects[summary["project_id"]]["name"] == "Finance"
    assert env.guards.is_linked(summary["project_id"]) is True


@pytest.mark.parametrize("group_name", ["Taken", "TAKEN", "  taken "])
def test_group_links_to_existing_project_with_the_same_name(env, group_name):
    group = env.svc.create_group(group_body(group_name, external_id="67a0834e"))
    env.run()
    assert env.project_of(group["id"]) == 1
    assert env.platform.projects == {1: env.platform.projects[1]}   # nothing created
    assert env.guards.is_linked(1) is True
    assert "SCIM_PROJECT_LINKED" in {e["reason_code"] for e in env.platform.audit}


def test_several_projects_with_the_name_is_an_error_until_renamed(env):
    env.platform.projects[2] = {"id": 2, "name": "taken", "suspended": False}
    group = env.svc.create_group(group_body("Taken"))
    env.run()
    summary = env.svc.group_summary(group["id"])
    assert summary["status"] == "error" and summary["project_id"] is None and "2 projects" in summary["error"]
    assert set(env.platform.projects) == {1, 2}
    env.platform.rename_project(2, "Taken (old)")
    env.run()
    assert env.project_of(group["id"]) == 1


def test_suspended_project_is_not_matched(env):
    env.platform.set_project_suspended(1, True)
    group = env.svc.create_group(group_body("Taken"))
    env.run()
    assert env.project_of(group["id"]) not in (None, 1)


def test_project_linked_to_another_group_is_not_matched(env):
    alpha = env.svc.create_group(group_body("Alpha"))
    env.run()
    alpha_project = env.project_of(alpha["id"])
    env.platform.rename_project(alpha_project, "Beta")
    beta = env.svc.create_group(group_body("Beta"))
    env.run()
    assert env.project_of(beta["id"]) not in (None, alpha_project)
    assert env.project_of(alpha["id"]) == alpha_project


def test_personal_project_is_never_matched(env):
    env.platform.projects[2] = {"id": 2, "name": "project_user_9", "suspended": False}
    group = env.svc.create_group(group_body("project_user_9"))
    env.run()
    project_id = env.project_of(group["id"])
    assert project_id not in (None, 2) and env.platform.projects[project_id]["name"] == "group-project_user_9"


def test_members_added_as_viewer_and_accounts_created_on_demand(env):
    jane, new = users(env, "jane@contoso.com", "new@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"], new["id"]]))
    env.run()
    new_id = env.platform.users["new@contoso.com"]["id"]
    assert env.members(group["id"]) == {5: ["viewer"], new_id: ["viewer"]}
    assert env.platform.created_users == ["new@contoso.com"]
    assert env.svc.user_link(new["id"]) == new_id


def test_existing_role_is_kept_on_resync(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    env.platform.members[env.project_of(group["id"])][5] = ["admin"]
    env.run()
    assert env.members(group["id"]) == {5: ["admin"]}


def test_project_creation_failure_marks_error_and_retries(env):
    env.platform.fail_create_project = True
    group = env.svc.create_group(group_body("Team"))
    env.run()
    summary = env.svc.group_summary(group["id"])
    assert summary["status"] == "error" and summary["error"]
    env.platform.fail_create_project = False
    env.run()
    assert env.svc.group_summary(group["id"])["status"] == "active"


def test_group_write_notifies_change(env):
    group = env.svc.create_group(group_body("Team"))
    assert group["id"] in env.changed


def test_create_group_twice_is_409(env):
    env.svc.create_group(group_body("Team"))
    with pytest.raises(protocol.ScimError) as exc:
        env.svc.create_group(group_body("Team"))
    assert exc.value.status == 409


def test_filter_groups_and_excluded_members(env):
    jane, = users(env, "jane@contoso.com")
    env.svc.create_group(group_body("Team", members=[jane["id"]]))
    found = env.svc.list_groups('displayName eq "Team"', excluded_attributes="members")
    assert found["totalResults"] == 1 and "members" not in found["Resources"][0]


# ---------- removal sync (AC-7) ----------

def test_member_removed_from_group_is_removed_from_project(env):
    jane, bob = users(env, "jane@contoso.com", "bob@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"], bob["id"]]))
    env.run()
    env.svc.patch_group(group["id"], patch(("Remove", f'members[value eq "{jane["id"]}"]', None)))
    env.run()
    assert 5 not in env.members(group["id"]) and len(env.members(group["id"])) == 1


def test_deactivated_user_is_removed_and_suspended_then_restored(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    env.svc.patch_user(jane["id"], patch(("Replace", "active", "False")))
    env.run()
    assert env.members(group["id"]) == {}
    assert env.platform.is_user_suspended(5) is True
    env.svc.patch_user(jane["id"], patch(("Replace", "active", "True")))
    env.run()
    assert env.platform.is_user_suspended(5) is False
    assert env.members(group["id"]) == {5: ["viewer"]}


def test_reactivation_does_not_unsuspend_a_user_suspended_by_someone_else(env):
    env.platform.users["jane@contoso.com"]["suspended"] = True
    jane, = users(env, "jane@contoso.com")
    env.svc.patch_user(jane["id"], patch(("Replace", "active", "False")))
    env.svc.patch_user(jane["id"], patch(("Replace", "active", "True")))
    env.run()
    assert env.platform.is_user_suspended(5) is True


@pytest.mark.parametrize("account", [
    {"id": 6, "email": "boss@contoso.com", "platform_admin": True},
    {"id": 7, "email": "system_user_3@centry.user"},
])
def test_platform_admins_and_system_users_are_never_suspended(env, account):
    env.platform.users[account["email"]] = dict(account, suspended=False)
    scim_user = env.svc.create_user(user_body(account["email"]))
    assert env.svc.user_link(scim_user["id"]) == account["id"]
    env.svc.patch_user(scim_user["id"], patch(("Replace", "active", "False")))
    env.run()
    env.svc.delete_user(scim_user["id"])
    env.run()
    assert env.platform.is_user_suspended(account["id"]) is False


def test_deleted_user_is_removed_and_suspended(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    env.svc.delete_user(jane["id"])
    env.run()
    assert env.members(group["id"]) == {}
    assert env.platform.is_user_suspended(5) is True


def test_member_before_the_link_stays_manual(env):
    """ AC-13a: a member of the existing project keeps their role and is never removed by the sync """
    env.platform.members[1] = {5: ["editor"]}
    jane, bob = users(env, "jane@contoso.com", "bob@contoso.com")
    group = env.svc.create_group(group_body("Taken", members=[jane["id"], bob["id"]]))
    env.run()
    bob_id = env.platform.users["bob@contoso.com"]["id"]
    assert env.platform.members[1] == {5: ["editor"], bob_id: ["viewer"]}
    assert env.guards.synced_user_ids(1) == {bob_id}
    env.svc.patch_group(group["id"], patch(("Remove", "members", None)))
    env.svc.delete_user(jane["id"])
    env.run()
    assert env.platform.members[1] == {5: ["editor"]}


def test_admin_added_by_platform_admin_is_kept_by_sync(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    project_id = env.project_of(group["id"])
    env.platform.members[project_id][42] = ["admin"]   # added by an ELITEA admin, not in the IdP group
    env.svc.patch_group(group["id"], patch(("Remove", "members", None)))
    env.run()
    assert env.platform.members[project_id] == {42: ["admin"]}


def test_member_not_granted_by_scim_is_never_removed(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    env.platform.members[env.project_of(group["id"])][77] = ["system"]   # e.g. the project's system user
    env.svc.patch_group(group["id"], patch(("Remove", "members", None)))
    env.run()
    assert env.members(group["id"]) == {77: ["system"]}


# ---------- nesting (AC-8, AC-9) ----------

def _nested(env):
    a_user, b_user, c_user = users(env, "a@contoso.com", "b@contoso.com", "c@contoso.com")
    a = env.svc.create_group(group_body("A", members=[a_user["id"]], external_id="ext-a"))
    b = env.svc.create_group(group_body("B", members=[b_user["id"]], external_id="ext-b"))
    c = env.svc.create_group(group_body("C", members=[c_user["id"]], external_id="ext-c"))
    return a, b, c


def ids(env, *emails):
    return {env.platform.users[e]["id"] for e in emails}


def test_nested_group_users_are_added_to_parent(env):
    a, b, _ = _nested(env)
    env.sync.set_edges({"ext-a": ["ext-b"]})
    env.run()
    assert set(env.members(a["id"])) == ids(env, "a@contoso.com", "b@contoso.com")
    assert set(env.members(b["id"])) == ids(env, "b@contoso.com")


def test_nesting_is_transitive_and_cycle_safe(env):
    a, b, c = _nested(env)
    env.sync.set_edges({"ext-a": ["ext-b"], "ext-b": ["ext-c"], "ext-c": ["ext-a"]})
    env.run()
    everyone = ids(env, "a@contoso.com", "b@contoso.com", "c@contoso.com")
    for group in (a, b, c):
        assert set(env.members(group["id"])) == everyone


def test_unassigned_child_ids_are_ignored(env):
    a, _, _ = _nested(env)
    env.sync.set_edges({"ext-a": ["not-provisioned"]})
    env.run()
    assert set(env.members(a["id"])) == ids(env, "a@contoso.com")


def test_removing_user_from_child_removes_from_parent(env):
    a, b, _ = _nested(env)
    env.sync.set_edges({"ext-a": ["ext-b"]})
    env.run()
    b_scim = env.svc.list_users('userName eq "b@contoso.com"')["Resources"][0]["id"]
    env.svc.patch_group(b["id"], patch(("Remove", f'members[value eq "{b_scim}"]', None)))
    env.run()
    assert set(env.members(a["id"])) == ids(env, "a@contoso.com")


def test_user_kept_in_parent_while_another_path_remains(env):
    a, b, _ = _nested(env)
    b_scim = env.svc.list_users('userName eq "b@contoso.com"')["Resources"][0]["id"]
    env.svc.patch_group(a["id"], patch(("Add", "members", [{"value": b_scim}])))
    env.sync.set_edges({"ext-a": ["ext-b"]})
    env.run()
    env.sync.set_edges({})
    env.run()
    assert set(env.members(a["id"])) == ids(env, "a@contoso.com", "b@contoso.com")


def test_failed_graph_pull_keeps_edges_and_removes_nobody(env):
    a, _, _ = _nested(env)
    env.sync.set_edges({"ext-a": ["ext-b"]})
    env.run()
    env.sync.pull_edges(lambda external_ids: (_ for _ in ()).throw(RuntimeError("throttled")))
    env.run()
    assert set(env.members(a["id"])) == ids(env, "a@contoso.com", "b@contoso.com")
    assert env.sync.graph_status()["error"]


def test_graph_pull_replaces_edges(env):
    a, _, c = _nested(env)
    env.sync.pull_edges(lambda external_ids: {"ext-a": ["ext-c"]})
    env.run()
    assert set(env.members(a["id"])) == ids(env, "a@contoso.com", "c@contoso.com")
    assert env.sync.graph_status()["error"] is None


# ---------- rename and removal (AC-10, AC-11) ----------

def test_group_rename_keeps_the_elitea_project_name(env):
    group = env.svc.create_group(group_body("Team"))
    env.run()
    project_id = env.project_of(group["id"])
    env.platform.rename_project(project_id, "Team (renamed in ELITEA)")
    env.svc.patch_group(group["id"], patch(("Replace", "displayName", "Team / 2026")))
    env.sync.sync_all(full=True)
    assert env.project_of(group["id"]) == project_id
    assert env.platform.projects[project_id]["name"] == "Team (renamed in ELITEA)"
    assert env.sync.overview()[0]["display_name"] == "Team / 2026"


def test_group_delete_removes_synced_members_keeps_manual_and_suspends(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    project_id = env.project_of(group["id"])
    env.platform.members[project_id][42] = ["editor"]   # added by hand
    env.svc.delete_group(group["id"])
    env.run()
    assert env.platform.projects[project_id]["suspended"] is True
    assert env.guards.is_linked(project_id) is False
    assert env.platform.members[project_id] == {42: ["editor"]}
    assert env.guards.synced_user_ids(project_id) == frozenset()


def test_deleted_linked_project_is_mapped_again(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    first = env.project_of(group["id"])
    env.platform.delete_project(first)
    env.sync.sync_all(full=True)
    second = env.project_of(group["id"])
    assert second not in (None, first)
    assert env.platform.members[second] == {5: ["viewer"]}
    assert env.guards.is_linked(first) is False


def test_unlink_moves_the_group_to_a_renamed_manual_project(env):
    """ AC-19: auto-created project → unlink → a manual project renamed to the group name is linked """
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    auto = env.project_of(group["id"])
    env.platform.projects[9] = {"id": 9, "name": "Legacy team", "suspended": False}
    env.platform.members[9] = {77: ["admin"]}
    env.platform.rename_project(9, "Team")
    env.platform.rename_project(auto, "Team (auto)")
    env.sync.unlink(group["id"])
    assert env.svc.group_summary(group["id"])["status"] == "pending"
    assert env.platform.projects[auto]["suspended"] is False and env.platform.members[auto] == {}
    env.run()
    assert env.project_of(group["id"]) == 9
    assert env.platform.members[9] == {77: ["admin"], 5: ["viewer"]}
    assert "SCIM_PROJECT_UNLINKED" in {e["reason_code"] for e in env.platform.audit}


# ---------- guards (AC-12, AC-13) ----------

def test_guards_protect_only_synced_members(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    project_id = env.project_of(group["id"])
    env.platform.members[project_id][42] = ["editor"]   # added by hand
    g = env.guards
    assert project_id in g.linked_ids()
    assert g.synced_user_ids(project_id) == {5}
    assert g.refusal(project_id, [42]) is None                      # remove a manual member
    assert g.refusal(project_id, [42], roles=[]) is None
    assert g.refusal(project_id, [5], roles=["editor"]) is None     # roles of a synced member
    body, status = g.refusal(project_id, [5, 42])                     # remove a synced member
    assert status == 403 and body["scim_synced"] == [5]
    assert g.refusal(project_id, [5], roles=[])[1] == 403


def test_guards_allow_everything_for_normal_projects(env):
    assert env.guards.synced_user_ids(1) == frozenset()
    assert env.guards.refusal(1, [9]) is None and env.guards.refusal(1, [9], roles=[]) is None


# ---------- stable ids (AC-17) ----------

def test_user_with_an_external_id_in_use_is_409(env):
    env.svc.create_user(user_body("jane@contoso.com", external_id="oid-1"))
    with pytest.raises(protocol.ScimError) as exc:
        env.svc.create_user(user_body("jane.doe@contoso.com", external_id="oid-1"))
    assert exc.value.status == 409 and exc.value.scim_type == "uniqueness"


def test_group_with_an_external_id_in_use_is_409(env):
    env.svc.create_group(group_body("Team", external_id="gid-1"))
    with pytest.raises(protocol.ScimError) as exc:
        env.svc.create_group(group_body("Team 2", external_id="gid-1"))
    assert exc.value.status == 409 and exc.value.scim_type == "uniqueness"


def test_external_id_of_a_deleted_user_can_be_used_again(env):
    jane = env.svc.create_user(user_body("jane@contoso.com", external_id="oid-1"))
    env.svc.delete_user(jane["id"])
    assert env.svc.create_user(user_body("jane@contoso.com", external_id="oid-1"))["id"] != jane["id"]


def test_email_change_keeps_the_account_and_membership(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    renamed = dict(user_body("jane.smith@contoso.com", external_id="oid-jane@contoso.com"))
    env.svc.replace_user(jane["id"], renamed)
    env.run()
    assert env.svc.user_link(jane["id"]) == 5
    assert env.members(group["id"]) == {5: ["viewer"]}
    assert env.platform.created_users == []


# ---------- admin overview (AC-14) ----------

def test_group_overview(env):
    a, b, _ = _nested(env)
    env.sync.set_edges({"ext-a": ["ext-b"]})
    env.run()
    rows = {row["display_name"]: row for row in env.sync.overview()}
    assert rows["A"]["status"] == "active" and rows["A"]["project_name"] == "A"
    assert rows["A"]["member_count"] == 1 and rows["A"]["effective_member_count"] == 2
    assert rows["A"]["children"] == ["B"] and rows["B"]["parents"] == ["A"]
    assert rows["A"]["last_activity_at"] is not None


# ---------- audit (AC-15) ----------

def test_writes_and_lifecycle_are_audited_without_secrets(env):
    issued = env.svc.create_token("t", created_by=1)
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    env.svc.delete_group(group["id"])
    env.run()
    codes = {e["reason_code"] for e in env.platform.audit}
    assert {"SCIM_TOKEN_CREATED", "SCIM_USER_CREATED", "SCIM_GROUP_CREATED", "SCIM_PROJECT_CREATED",
            "SCIM_MEMBER_ADDED", "SCIM_GROUP_DELETED", "SCIM_PROJECT_SUSPENDED"} <= codes
    for event in env.platform.audit:
        assert event["event_type"] == "lifecycle"
        assert issued["token"] not in repr(event)
        assert all(len(str(v)) <= 256 for v in event.values())


# ---------- replicas and efficiency (review of #70) ----------

def test_two_replicas_create_one_project(env):
    """ Two pylon_main replicas run the sync on the same DB: the group gets exactly one project """
    other = projects_module.ProjectSync(env.get_session, env.platform)
    group = env.svc.create_group(group_body("Team"))
    env.sync.sync_all()
    other.sync_all()
    names = [p["name"] for p in env.platform.projects.values()]
    assert names.count("Team") == 1
    assert env.svc.group_summary(group["id"])["project_id"] is not None


def test_no_db_session_is_held_across_platform_calls(env):
    env.platform.get_session = env.get_session
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    env.svc.patch_group(group["id"], patch(("Remove", "members", None)))
    env.run()
    assert env.platform.sessions_during_calls and set(env.platform.sessions_during_calls) == {0}


def test_only_changed_groups_are_synced(env):
    jane, bob = users(env, "jane@contoso.com", "bob@contoso.com")
    a = env.svc.create_group(group_body("A", members=[jane["id"]]))
    b = env.svc.create_group(group_body("B", members=[bob["id"]]))
    env.run()
    env.platform.member_reads.clear()
    env.svc.patch_group(a["id"], patch(("Remove", "members", None)))
    env.run()
    assert env.platform.member_reads == [env.project_of(a["id"])]
    env.platform.member_reads.clear()
    env.run()   # nothing changed since
    assert env.platform.member_reads == []
    assert env.project_of(b["id"])


def test_full_sync_still_reaches_every_group(env):
    """ Sync now / schedule: a full pass re-checks every group even without changes """
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("A", members=[jane["id"]]))
    env.run()
    env.platform.members[env.project_of(group["id"])].pop(5)   # drifted outside SCIM
    env.sync.sync_all(full=True)
    assert env.members(group["id"]) == {5: ["viewer"]}


def test_project_user_cache_is_cleared_once_per_project(env):
    jane, bob = users(env, "jane@contoso.com", "bob@contoso.com")
    env.svc.create_group(group_body("Team", members=[jane["id"], bob["id"]]))
    env.run()
    assert len(env.platform.cache_clears) == 1 and len(env.platform.cache_clears[0]) == 2


def test_nesting_change_marks_parents_for_sync(env):
    a, b, _ = _nested(env)
    env.run()
    env.platform.member_reads.clear()
    env.sync.set_edges({"ext-a": ["ext-b"]})
    env.run()
    assert env.platform.member_reads == [env.project_of(a["id"])]
    assert set(env.members(a["id"])) == ids(env, "a@contoso.com", "b@contoso.com")


def test_replica_without_the_lock_skips_the_pass(env):
    from contextlib import contextmanager

    @contextmanager
    def busy():
        yield False

    other = projects_module.ProjectSync(env.get_session, env.platform, lock=busy)
    env.svc.create_group(group_body("Team"))
    assert other.sync_all()["skipped"] is True
    assert env.platform.projects == {1: env.platform.projects[1]}   # nothing created by the busy replica


def test_group_that_got_a_project_meanwhile_is_not_created_again(env):
    """ A replica read the group as project-less, another created the project before this one acted """
    group = env.svc.create_group(group_body("Team"))
    env.run()
    first = env.project_of(group["id"])
    stale = projects_module.ProjectSync(env.get_session, env.platform)
    row = type("Row", (), {"id": group["id"], "display_name": "Team", "status": "pending", "project_id": None})
    stale._link_or_create(row, {"created": 0, "linked": 0, "errors": 0})   # pylint: disable=W0212
    assert env.project_of(group["id"]) == first
    assert [p["name"] for p in env.platform.projects.values()].count("Team") == 1


def test_project_changes_notify_other_replicas(env):
    notified = []
    env.sync.on_projects_changed = lambda: notified.append(True)
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    assert notified
    notified.clear()
    env.svc.delete_group(group["id"])
    env.run()
    assert notified


# ---------- review of iteration 3 ----------

def test_unlink_without_renaming_links_the_same_project_again(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    first = env.project_of(group["id"])
    env.sync.unlink(group["id"])
    env.run()
    assert env.project_of(group["id"]) == first
    assert [p["name"] for p in env.platform.projects.values()].count("Team") == 1
    assert env.platform.members[first] == {5: ["viewer"]}


def test_unlink_waits_for_another_replica(env):
    from contextlib import contextmanager

    @contextmanager
    def busy():
        yield False

    group = env.svc.create_group(group_body("Team"))
    env.run()
    other = projects_module.ProjectSync(env.get_session, env.platform, lock=busy)
    with pytest.raises(RuntimeError):
        other.unlink(group["id"])
    assert env.project_of(group["id"]) is not None


def test_failed_retire_keeps_the_group_removed_and_retries(env):
    jane, = users(env, "jane@contoso.com")
    group = env.svc.create_group(group_body("Team", members=[jane["id"]]))
    env.run()
    project_id = env.project_of(group["id"])
    original = env.platform.remove_member
    env.platform.remove_member = lambda *a: (_ for _ in ()).throw(RuntimeError("platform down"))
    env.svc.delete_group(group["id"])
    env.run()
    summary = env.sync.overview()[0]
    assert summary["status"] == "removed" and summary["error"]
    assert len(env.platform.projects) == 2   # no new project for the deleted group
    env.platform.remove_member = original
    env.run()
    assert env.platform.projects[project_id]["suspended"] is True and env.platform.members[project_id] == {}
    assert env.sync.overview()[0]["error"] is None


def test_removed_group_whose_project_was_deleted_stays_removed(env):
    group = env.svc.create_group(group_body("Team"))
    env.run()
    env.platform.delete_project(env.project_of(group["id"]))
    env.svc.delete_group(group["id"])
    env.run()
    row = env.sync.overview()[0]
    assert row["status"] == "removed" and row["project_id"] is None
    assert len(env.platform.projects) == 1


@pytest.mark.parametrize("change", ["replace", "patch"])
def test_external_id_of_another_live_group_is_409_on_update(env, change):
    env.svc.create_group(group_body("A", external_id="gid-a"))
    b = env.svc.create_group(group_body("B", external_id="gid-b"))
    with pytest.raises(protocol.ScimError) as exc:
        if change == "replace":
            env.svc.replace_group(b["id"], group_body("B", external_id="gid-a"))
        else:
            env.svc.patch_group(b["id"], patch(("Replace", "externalId", "gid-a")))
    assert exc.value.status == 409


def test_external_id_of_another_live_user_is_409_on_update(env):
    env.svc.create_user(user_body("jane@contoso.com", external_id="oid-1"))
    bob = env.svc.create_user(user_body("bob@contoso.com", external_id="oid-2"))
    with pytest.raises(protocol.ScimError) as exc:
        env.svc.replace_user(bob["id"], user_body("bob@contoso.com", external_id="oid-1"))
    assert exc.value.status == 409
    assert env.svc.replace_user(bob["id"], user_body("bob@contoso.com", external_id="oid-2"))["externalId"] == "oid-2"
