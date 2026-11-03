""" The platform calls SCIM provisioning makes (#5202): auth users, projects, membership, audit """
from pylon.core.tools import log  # pylint: disable=E0401
from tools import auth, this  # pylint: disable=E0401

SERVICE_USER_EMAIL = "scim_provisioner@centry.user"


class Platform:
    def __init__(self, module):
        self.module = module
        self.rpc = module.context.rpc_manager
        self._service_user_id = None

    # users

    @staticmethod
    def find_user(email):
        try:
            return auth.get_user(email=email)
        except Exception:  # pylint: disable=W0703
            return None

    def ensure_user(self, email):
        """ The account with this email, created (with its Keycloak user) like a manual add by email """
        user = self.find_user(email)
        if user:
            return user["id"]
        from plugins.projects.rpc.poc import create_keycloak_user  # pylint: disable=C0415,E0401
        try:
            create_keycloak_user(email, rpc_manager=self.rpc)
        except Exception as exc:  # pylint: disable=W0703
            log.warning("SCIM: Keycloak user %s not created: %s", email, exc)
        user_id = auth.add_user(email)
        auth.add_user_provider(user_id, email)
        auth.add_user_group(user_id, 1)
        return user_id

    @staticmethod
    def set_user_suspended(user_id, suspended):
        auth.update_user(id_=user_id, suspended=bool(suspended))

    @staticmethod
    def is_user_suspended(user_id):
        try:
            return bool(auth.get_user(user_id=user_id).get("suspended"))
        except Exception:  # pylint: disable=W0703
            return False

    @staticmethod
    def is_protected_account(user_id):
        """ Platform admins and system users: never suspended by SCIM """
        try:
            email = auth.get_user(user_id=user_id).get("email") or ""
            if email.endswith("@centry.user"):
                return True
            roles = auth.get_user_roles(user_id, mode="administration") or []
            return bool({"admin", "super_admin", "system"} & set(roles))
        except Exception:  # pylint: disable=W0703
            return True   # unknown: do not suspend

    def service_user_id(self):
        """ The account SCIM requests act as and SCIM projects are owned by; created on first use """
        if self._service_user_id:
            return self._service_user_id
        user = self.find_user(SERVICE_USER_EMAIL)
        if user:
            self._service_user_id = user["id"]
            return self._service_user_id
        try:
            user_id = auth.add_user(SERVICE_USER_EMAIL, "SCIM provisioning")
            auth.add_user_provider(user_id, SERVICE_USER_EMAIL)
            self._service_user_id = user_id
        except Exception:  # pylint: disable=W0703
            log.exception("SCIM: the provisioning service user could not be created")
        return self._service_user_id

    # projects

    def project_name(self, project_id):
        return self.rpc.timeout(30).projects_scim_name(project_id=project_id)

    def create_project(self, name):
        owner_id = self.service_user_id()
        if not owner_id:
            raise RuntimeError("The SCIM service user is not available")
        return self.rpc.timeout(600).projects_scim_create(name=name, owner_id=owner_id)

    def rename_project(self, project_id, name):
        self.rpc.timeout(30).projects_scim_rename(project_id=project_id, name=name)

    def set_project_suspended(self, project_id, suspended):
        self.rpc.timeout(30).projects_scim_set_suspended(project_id=project_id, suspended=suspended)

    # membership: the SCIM path through the guarded RPCs

    def project_user_ids(self, project_id):
        return self.rpc.timeout(30).admin_get_users_ids_in_project(project_id)

    def add_member(self, project_id, user_id, role):
        self.rpc.timeout(30).admin_add_user_to_project(project_id, user_id, [role], scim_sync=True)
        self.rpc.timeout(10).clear_user_projects_cache([user_id])
        return True

    def remove_member(self, project_id, user_id):
        self.rpc.timeout(30).admin_remove_users_from_project(project_id, [user_id], scim_sync=True)
        self.rpc.timeout(10).clear_user_projects_cache([user_id])

    @staticmethod
    def record_audit(event):
        this.for_module("tracing").module.security_audit_record_autocommit(event)
