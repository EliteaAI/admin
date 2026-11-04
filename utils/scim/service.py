""" SCIM Users / Groups / tokens on the admin plugin's tables (#5202).

``platform`` gives the calls outside this plugin's tables: find_user(email), record_audit(event).
Nothing here creates projects or changes project access: ``on_group_changed(group_id)`` and
``on_user_changed(scim_user_id)`` let the caller sync projects (utils/scim/projects.py).
Deleted users and groups are kept as tombstones (hidden from SCIM) so the sync can undo what they granted.
"""
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from pylon.core.tools import log  # pylint: disable=E0401

from ...models.scim import ScimGroup, ScimGroupMember, ScimToken, ScimUser
from . import protocol, tokens
from .protocol import ScimError

GROUP_PENDING = "pending"
GROUP_ACTIVE = "active"
GROUP_REMOVED = "removed"
GROUP_ERROR = "error"


def now():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.isoformat() if value else None


def audit_event(reason_code, target_ref, project_id=None, outcome="success", caller_ref="scim"):
    event = {"event_type": "lifecycle", "reason_code": reason_code, "caller_ref": caller_ref,
             "target_ref": str(target_ref)[:256], "outcome": outcome}
    if project_id is not None:
        event["project_id"] = project_id
    return event


class ScimService:
    def __init__(self, get_session, platform, on_group_changed=None, on_user_changed=None, base_url=""):
        self.get_session = get_session
        self.platform = platform
        self.on_group_changed = on_group_changed or (lambda group_id: None)
        self.on_user_changed = on_user_changed or (lambda scim_user_id: None)
        self.base_url = base_url

    def _audit(self, *args, **kwargs):
        try:
            self.platform.record_audit(audit_event(*args, **kwargs))
        except Exception:  # pylint: disable=W0703
            log.exception("SCIM audit record failed")

    #
    # Tokens
    #

    @staticmethod
    def _token_row(row):
        return {"id": row.id, "name": row.name, "last4": row.last4, "created_by": row.created_by,
                "created_at": _iso(row.created_at), "last_used_at": _iso(row.last_used_at),
                "revoked_at": _iso(row.revoked_at)}

    def create_token(self, name, created_by):
        token, token_hash, last4 = tokens.generate()
        with self.get_session() as session:
            row = ScimToken(name=(name or "SCIM token")[:128], token_hash=token_hash, last4=last4,
                            created_by=created_by, created_at=now())
            session.add(row)
            session.commit()
            result = self._token_row(row) | {"token": token}
        self._audit("SCIM_TOKEN_CREATED", f"token:{result['id']}", caller_ref=f"user:{created_by}")
        return result

    def list_tokens(self):
        with self.get_session() as session:
            return [self._token_row(r) for r in session.scalars(select(ScimToken).order_by(ScimToken.id))]

    def revoke_token(self, token_id, revoked_by=None):
        with self.get_session() as session:
            row = session.get(ScimToken, token_id)
            if row is None:
                raise ScimError(404, "Token not found")
            if row.revoked_at is None:
                row.revoked_at = now()
                session.commit()
        self._audit("SCIM_TOKEN_REVOKED", f"token:{token_id}", caller_ref=f"user:{revoked_by}")

    def rotate_token(self, token_id, created_by):
        with self.get_session() as session:
            row = session.get(ScimToken, token_id)
            if row is None:
                raise ScimError(404, "Token not found")
            name = row.name
        self.revoke_token(token_id, revoked_by=created_by)
        return self.create_token(name, created_by)

    def verify_token(self, token) -> bool:
        if not isinstance(token, str) or not token.startswith(tokens.PREFIX):
            return False
        with self.get_session() as session:
            row = session.scalars(select(ScimToken).where(
                ScimToken.token_hash == tokens.hash_token(token), ScimToken.revoked_at.is_(None))).first()
            if row is None:
                return False
            row.last_used_at = now()
            session.commit()
            return True

    def has_tokens(self) -> bool:
        with self.get_session() as session:
            return session.scalar(select(func.count()).select_from(ScimToken).where(
                ScimToken.revoked_at.is_(None))) > 0

    #
    # Users
    #

    def _user_resource(self, row):
        resource = {
            "schemas": [protocol.USER], "id": row.id, "userName": row.user_name, "active": row.active,
            "meta": {"resourceType": "User", "created": _iso(row.created_at), "lastModified": _iso(row.updated_at),
                     "location": f"{self.base_url}/Users/{row.id}"},
        }
        if row.external_id:
            resource["externalId"] = row.external_id
        if row.display_name:
            resource["displayName"] = row.display_name
        if row.email:
            resource["emails"] = [{"value": row.email, "type": "work", "primary": True}]
        return resource

    def _apply_user(self, row, resource):
        user_name = resource.get("userName")
        if not user_name or not isinstance(user_name, str):
            raise ScimError(400, "userName is required", "invalidValue")
        row.user_name = user_name[:256]
        row.external_id = (resource.get("externalId") or None) and str(resource["externalId"])[:256]
        row.display_name = (resource.get("displayName") or None) and str(resource["displayName"])[:256]
        if "active" in resource:
            row.active = protocol.bool_value(resource["active"])
        row.email = protocol.primary_email(resource)
        self._link_account(row)

    def _link_account(self, row):
        """ Link the SCIM user to the ELITEA account with its email; never create one here """
        if row.elitea_user_id or not row.email:
            return
        try:
            user = self.platform.find_user(row.email)
        except Exception:  # pylint: disable=W0703
            user = None
        if user:
            row.elitea_user_id = user["id"]

    @staticmethod
    def _get_user_row(session, user_id):
        row = session.get(ScimUser, user_id)
        if row is None or row.deleted:
            raise ScimError(404, f"User {user_id} not found")
        return row

    def _user_name_taken(self, session, user_name, exclude_id=None):
        query = select(ScimUser.id).where(func.lower(ScimUser.user_name) == user_name.lower(),
                                          ScimUser.deleted.is_(False))
        if exclude_id:
            query = query.where(ScimUser.id != exclude_id)
        return session.scalars(query).first() is not None

    def create_user(self, resource):
        with self.get_session() as session:
            if self._user_name_taken(session, str(resource.get("userName") or "")):
                raise ScimError(409, "userName already exists", "uniqueness")
            row = ScimUser(active=True, created_at=now(), updated_at=now())
            self._apply_user(row, resource)
            session.add(row)
            session.commit()
            result = self._user_resource(row)
        self._audit("SCIM_USER_CREATED", f"scim_user:{result['id']}")
        return result

    def get_user(self, user_id):
        with self.get_session() as session:
            return self._user_resource(self._get_user_row(session, user_id))

    def user_link(self, user_id):
        with self.get_session() as session:
            return self._get_user_row(session, user_id).elitea_user_id

    def list_users(self, filter_text=None, start_index=1, count=protocol.DEFAULT_COUNT):
        parsed = protocol.parse_filter(filter_text)
        query = select(ScimUser).where(ScimUser.deleted.is_(False))
        if parsed:
            attribute, value = parsed
            column = {"username": ScimUser.user_name, "externalid": ScimUser.external_id}.get(attribute)
            if column is None:
                raise ScimError(400, "Unsupported filter attribute for Users", "invalidFilter")
            query = query.where(func.lower(column) == value.lower())
        return self._page(query.order_by(ScimUser.created_at, ScimUser.id), self._user_resource, start_index, count)

    def replace_user(self, user_id, resource):
        with self.get_session() as session:
            row = self._get_user_row(session, user_id)
            if self._user_name_taken(session, str(resource.get("userName") or ""), exclude_id=user_id):
                raise ScimError(409, "userName already exists", "uniqueness")
            self._apply_user(row, resource)
            row.updated_at = now()
            session.commit()
            result = self._user_resource(row)
        self._audit("SCIM_USER_UPDATED", f"scim_user:{user_id}")
        self._mark_user_groups(user_id)
        self.on_user_changed(user_id)
        return result

    def patch_user(self, user_id, body):
        operations = protocol.parse_patch(body)
        with self.get_session() as session:
            row = self._get_user_row(session, user_id)
            resource = self._user_resource(row)
            for op, path, value in operations:
                updates = value if (not path and isinstance(value, dict)) else {path: value}
                for key, item in updates.items():
                    self._patch_user_attribute(resource, op, key or "", item)
            self._apply_user(row, resource)
            row.updated_at = now()
            session.commit()
            result = self._user_resource(row)
        self._audit("SCIM_USER_UPDATED", f"scim_user:{user_id}")
        self._mark_user_groups(user_id)
        self.on_user_changed(user_id)
        return result

    def _mark_user_groups(self, user_id):
        """ A user's active state or email changed: every group they are in needs a sync """
        with self.get_session() as session:
            group_ids = select(ScimGroupMember.group_id).where(ScimGroupMember.user_id == user_id)
            session.query(ScimGroup).filter(ScimGroup.id.in_(group_ids)).update(
                {ScimGroup.dirty: True}, synchronize_session=False)
            session.commit()

    @staticmethod
    def _patch_user_attribute(resource, op, key, value):
        name = key.lower()
        if name.startswith("emails"):
            if op == "remove":
                resource.pop("emails", None)
            else:
                resource["emails"] = [{"value": value, "type": "work", "primary": True}]
            return
        target = {"username": "userName", "displayname": "displayName", "active": "active",
                  "externalid": "externalId"}.get(name)
        if target is None:
            return  # attributes ELITEA does not keep (name.givenName, title, ...) are accepted and ignored
        if op == "remove":
            resource.pop(target, None)
        else:
            resource[target] = value

    def delete_user(self, user_id):
        """ Tombstone: hidden from SCIM, out of every group, inactive; its userName is freed for a new user """
        with self.get_session() as session:
            row = self._get_user_row(session, user_id)
            group_ids = list(session.scalars(select(ScimGroupMember.group_id).where(ScimGroupMember.user_id == user_id)))
            session.query(ScimGroupMember).filter(ScimGroupMember.user_id == user_id).delete()
            session.query(ScimGroup).filter(ScimGroup.id.in_(group_ids)).update(
                {ScimGroup.dirty: True}, synchronize_session=False)
            row.deleted = True
            row.active = False
            row.user_name = f"deleted:{row.id}:{row.user_name}"[:256]
            row.updated_at = now()
            session.commit()
        self._audit("SCIM_USER_DELETED", f"scim_user:{user_id}")
        self.on_user_changed(user_id)
        for group_id in group_ids:
            self.on_group_changed(group_id)

    #
    # Groups
    #

    def _group_resource(self, session, row, include_members=True):
        resource = {
            "schemas": [protocol.GROUP], "id": row.id, "displayName": row.display_name,
            "meta": {"resourceType": "Group", "created": _iso(row.created_at), "lastModified": _iso(row.updated_at),
                     "location": f"{self.base_url}/Groups/{row.id}"},
        }
        if row.external_id:
            resource["externalId"] = row.external_id
        if include_members:
            members = session.execute(
                select(ScimUser.id, ScimUser.user_name).join(ScimGroupMember, ScimGroupMember.user_id == ScimUser.id)
                .where(ScimGroupMember.group_id == row.id).order_by(ScimUser.user_name)).all()
            resource["members"] = [{"value": m.id, "display": m.user_name} for m in members]
        return resource

    @staticmethod
    def _get_group_row(session, group_id):
        row = session.get(ScimGroup, group_id)
        if row is None or row.status == GROUP_REMOVED:
            raise ScimError(404, f"Group {group_id} not found")
        return row

    def _set_name(self, session, row, name):
        if not name or not isinstance(name, str):
            raise ScimError(400, "displayName is required", "invalidValue")
        taken = session.scalars(select(ScimGroup.id).where(
            func.lower(ScimGroup.display_name) == name.lower(), ScimGroup.id != row.id,
            ScimGroup.status != GROUP_REMOVED)).first()
        if taken:
            raise ScimError(409, "displayName already exists", "uniqueness")
        row.display_name = name[:256]

    @staticmethod
    def _add_members(session, group_id, members) -> int:
        ids = [m.get("value") for m in (members or []) if isinstance(m, dict) and m.get("value")]
        known = set(session.scalars(select(ScimUser.id).where(
            ScimUser.id.in_(ids), ScimUser.deleted.is_(False)))) if ids else set()
        present = set(session.scalars(select(ScimGroupMember.user_id).where(ScimGroupMember.group_id == group_id)))
        added = 0
        for user_id in dict.fromkeys(ids):
            if user_id in known and user_id not in present:
                session.add(ScimGroupMember(group_id=group_id, user_id=user_id))
                added += 1
            elif user_id not in known:
                log.warning("SCIM: group %s member %s is not a provisioned user, ignored", group_id, user_id)
        return added

    @staticmethod
    def _remove_members(session, group_id, user_ids):
        query = session.query(ScimGroupMember).filter(ScimGroupMember.group_id == group_id)
        if user_ids is not None:
            query = query.filter(ScimGroupMember.user_id.in_(list(user_ids)))
        query.delete(synchronize_session=False)

    def create_group(self, resource):
        with self.get_session() as session:
            row = ScimGroup(status=GROUP_PENDING, dirty=True, created_at=now(), updated_at=now(),
                            last_activity_at=now())
            self._set_name(session, row, resource.get("displayName"))
            row.external_id = (resource.get("externalId") or None) and str(resource["externalId"])[:256]
            session.add(row)
            try:
                session.flush()
            except IntegrityError as exc:
                raise ScimError(409, "displayName already exists", "uniqueness") from exc
            self._add_members(session, row.id, resource.get("members"))
            session.commit()
            result = self._group_resource(session, row)
        self._audit("SCIM_GROUP_CREATED", f"scim_group:{result['id']}")
        self.on_group_changed(result["id"])
        return result

    def get_group(self, group_id, excluded_attributes=None):
        with self.get_session() as session:
            return self._group_resource(session, self._get_group_row(session, group_id),
                                        include_members=not _excludes_members(excluded_attributes))

    def list_groups(self, filter_text=None, start_index=1, count=protocol.DEFAULT_COUNT, excluded_attributes=None):
        parsed = protocol.parse_filter(filter_text)
        query = select(ScimGroup).where(ScimGroup.status != GROUP_REMOVED)
        if parsed:
            attribute, value = parsed
            column = {"displayname": ScimGroup.display_name, "externalid": ScimGroup.external_id}.get(attribute)
            if column is None:
                raise ScimError(400, "Unsupported filter attribute for Groups", "invalidFilter")
            query = query.where(func.lower(column) == value.lower())
        include_members = not _excludes_members(excluded_attributes)
        return self._page(query.order_by(ScimGroup.created_at, ScimGroup.id),
                          lambda row, session: self._group_resource(session, row, include_members),
                          start_index, count, with_session=True)

    def replace_group(self, group_id, resource):
        with self.get_session() as session:
            row = self._get_group_row(session, group_id)
            self._set_name(session, row, resource.get("displayName"))
            row.external_id = (resource.get("externalId") or None) and str(resource["externalId"])[:256]
            self._remove_members(session, group_id, None)
            self._add_members(session, group_id, resource.get("members"))
            row.updated_at = row.last_activity_at = now()
            row.dirty = True
            session.commit()
            result = self._group_resource(session, row)
        self._audit("SCIM_GROUP_UPDATED", f"scim_group:{group_id}")
        self.on_group_changed(group_id)
        return result

    def patch_group(self, group_id, body):
        operations = protocol.parse_patch(body)
        changed = False
        with self.get_session() as session:
            row = self._get_group_row(session, group_id)
            for op, path, value in operations:
                lowered = (path or "").lower()
                if not path and isinstance(value, dict):
                    if "displayName" in value:
                        self._set_name(session, row, value["displayName"])
                        changed = True
                    if "externalId" in value:
                        row.external_id = value["externalId"] and str(value["externalId"])[:256]
                    if "members" in value:
                        if op == "replace":
                            self._remove_members(session, group_id, None)
                        changed |= self._add_members(session, group_id, value["members"]) > 0 or op == "replace"
                elif lowered == "displayname":
                    self._set_name(session, row, value)
                    changed = True
                elif lowered == "externalid":
                    row.external_id = value and str(value)[:256]
                elif lowered == "members":
                    if op == "remove":
                        ids = None if value is None else [m.get("value") for m in value if isinstance(m, dict)]
                        self._remove_members(session, group_id, ids)
                        changed = True
                    else:
                        if op == "replace":
                            self._remove_members(session, group_id, None)
                        changed |= self._add_members(session, group_id, value) > 0 or op == "replace"
                elif protocol.member_filter_value(path) and op == "remove":
                    self._remove_members(session, group_id, [protocol.member_filter_value(path)])
                    changed = True
            row.updated_at = row.last_activity_at = now()
            row.dirty = row.dirty or changed
            session.commit()
        self._audit("SCIM_GROUP_UPDATED", f"scim_group:{group_id}")
        if changed:
            self.on_group_changed(group_id)
        return None

    def delete_group(self, group_id):
        """ Tombstone: the sync suspends the group's project; the name is freed for a new group """
        with self.get_session() as session:
            row = self._get_group_row(session, group_id)
            self._remove_members(session, group_id, None)
            row.status = GROUP_REMOVED
            row.dirty = True
            row.display_name = f"{row.display_name} (removed {row.id[:8]})"[:256]
            row.updated_at = row.last_activity_at = now()
            session.commit()
        self._audit("SCIM_GROUP_DELETED", f"scim_group:{group_id}")
        self.on_group_changed(group_id)

    #
    # Administration
    #

    @staticmethod
    def _summary(session, row):
        member_count = session.scalar(
            select(func.count()).select_from(ScimGroupMember).where(ScimGroupMember.group_id == row.id))
        return {
            "id": row.id, "display_name": row.display_name, "external_id": row.external_id,
            "project_id": row.project_id, "status": row.status, "error": row.error,
            "member_count": member_count, "last_activity_at": _iso(row.last_activity_at),
        }

    def group_summary(self, group_id):
        with self.get_session() as session:
            row = session.get(ScimGroup, group_id)
            if row is None:
                raise ScimError(404, f"Group {group_id} not found")
            return self._summary(session, row)

    #
    # Paging
    #

    def _page(self, query, render, start_index, count, with_session=False):
        with self.get_session() as session:
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.scalars(query.offset(start_index - 1).limit(count)).all() if count else []
            resources = [render(row, session) if with_session else render(row) for row in rows]
        return protocol.list_response(resources, total, start_index)


def _excludes_members(excluded_attributes):
    return "members" in [a.strip().lower() for a in (excluded_attributes or "").split(",")]
