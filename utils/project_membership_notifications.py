"""Publish notifications for manual team-project membership changes."""

from pylon.core.tools import log  # pylint: disable=E0401,E0611
from tools import this  # pylint: disable=E0401


_DEFAULTS = {
    "on_added": True,
    "on_removed": False,
}
_EVENT_SETTINGS = {
    "user_was_added_to_some_project_as_teammate": (
        "on_added",
        "You have been added to {project_name} project.",
    ),
    "user_was_removed_from_project": (
        "on_removed",
        "You have been removed from {project_name} project.",
    ),
}


def _read_notification_settings():
    """Read live elitea_core settings, applying defaults when config is unavailable or invalid."""
    settings = dict(_DEFAULTS)
    try:
        config = this.for_module("elitea_core").module.descriptor.config
    except Exception:  # pylint: disable=W0703
        log.warning("Cannot read project membership notification settings; using defaults", exc_info=True)
        return settings

    if not isinstance(config, dict):
        log.warning("Invalid elitea_core config for project membership notifications; using defaults")
        return settings
    if "notifications" not in config:
        return settings

    notifications = config["notifications"]
    if not isinstance(notifications, dict):
        log.warning("Invalid notifications config for project membership notifications; using defaults")
        return settings
    if "project_membership" not in notifications:
        return settings

    project_membership = notifications["project_membership"]
    if not isinstance(project_membership, dict):
        log.warning("Invalid project_membership config; using notification defaults")
        return settings

    for key, default in _DEFAULTS.items():
        if key not in project_membership:
            continue
        value = project_membership[key]
        if isinstance(value, bool):
            settings[key] = value
        else:
            log.warning(
                "Invalid project_membership.%s value type %s; using default %s",
                key,
                type(value).__name__,
                default,
            )
    return settings


def _get_team_project_name(module, project_id):
    """Return a project-name snapshot only for a project classified as team by projects RPC."""
    try:
        rpc = module.context.rpc_manager.timeout(5)
        if rpc.projects_get_project_kind(project_id) != "team":
            return None
        project = rpc.project_get_by_id(project_id)
    except Exception:  # pylint: disable=W0703
        log.exception("Cannot resolve project metadata for membership notification project_id=%s", project_id)
        return None

    if not isinstance(project, dict):
        log.warning("Missing project metadata for membership notification project_id=%s", project_id)
        return None
    project_name = project.get("name")
    if not isinstance(project_name, str) or not project_name.strip():
        log.warning("Invalid project name for membership notification project_id=%s", project_id)
        return None
    return project_name


def notify_project_membership_change(module, project_id, user_ids, event_type, actor_id=None):
    """Publish one inbox event per eligible user; notification failures never affect membership changes."""
    event_settings = _EVENT_SETTINGS.get(event_type)
    if event_settings is None:
        log.warning("Unsupported project membership notification event_type=%s", event_type)
        return

    setting, message_template = event_settings
    settings = _read_notification_settings()
    if not settings[setting]:
        return

    if event_type == "user_was_added_to_some_project_as_teammate" and actor_id is None:
        log.warning(
            "Skipping project membership notifications because actor is unknown; project_id=%s",
            project_id,
        )
        return

    eligible_ids = []
    invalid_count = 0
    for user_id in user_ids:
        if not isinstance(user_id, int) or isinstance(user_id, bool):
            invalid_count += 1
            continue
        if user_id != actor_id and user_id not in eligible_ids:
            eligible_ids.append(user_id)
    if invalid_count:
        log.warning(
            "Ignoring %d invalid recipients for membership notification event_type=%s project_id=%s",
            invalid_count,
            event_type,
            project_id,
        )
    if not eligible_ids:
        return

    project_name = _get_team_project_name(module, project_id)
    if project_name is None:
        return

    for user_id in eligible_ids:
        payload = {
            "project_id": project_id,
            "user_id": user_id,
            "event_type": event_type,
            "meta": {
                "project_name": project_name,
                "message": message_template.format(project_name=project_name),
            },
        }
        try:
            module.context.event_manager.fire_event("notifications_stream", payload)
        except Exception:  # pylint: disable=W0703
            log.exception(
                "Failed to publish membership notification event_type=%s project_id=%s user_id=%s",
                event_type,
                project_id,
                user_id,
            )
