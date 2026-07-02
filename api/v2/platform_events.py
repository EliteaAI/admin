"""Platform events API endpoint."""

from datetime import datetime

import flask

from tools import auth, db
from tools import api_tools, register_openapi

from ...services.platform_event import PlatformEventService


MAX_LIMIT = 100
DEFAULT_LIMIT = 50


def _parse_datetime(value: str) -> datetime:
    """Parse ISO 8601 datetime string."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class AdminAPI(api_tools.APIModeHandler):
    """Platform events API handler."""

    @register_openapi(
        name="List Platform Events",
        description="Query platform lifecycle events (restarts, reloads, starts).",
        parameters=[
            {"name": "pylon_id", "in": "query", "schema": {"type": "string"},
             "description": "Filter by pylon identifier."},
            {"name": "event_type", "in": "query", "schema": {"type": "string"},
             "description": "Filter by event type (restart_requested, reload_requested, pylon_started)."},
            {"name": "since", "in": "query", "schema": {"type": "string", "format": "date-time"},
             "description": "Filter events created at or after this time (ISO 8601)."},
            {"name": "until", "in": "query", "schema": {"type": "string", "format": "date-time"},
             "description": "Filter events created at or before this time (ISO 8601)."},
            {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50},
             "description": "Maximum number of results (1-100)."},
            {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0},
             "description": "Number of results to skip."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": ["runtime.plugins"],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": True, "editor": True, "viewer": False},
            "default": {"super_admin": True, "admin": False, "editor": False, "viewer": False},
        }
    })
    def get(self):
        """List platform events."""
        args = flask.request.args

        try:
            limit = int(args.get("limit", DEFAULT_LIMIT))
            offset = int(args.get("offset", 0))
        except ValueError:
            return {"error": "limit and offset must be integers"}, 400

        if limit < 1 or limit > MAX_LIMIT:
            return {"error": f"limit must be between 1 and {MAX_LIMIT}"}, 400
        if offset < 0:
            return {"error": "offset must be non-negative"}, 400

        since = None
        until = None
        try:
            if args.get("since"):
                since = _parse_datetime(args["since"])
            if args.get("until"):
                until = _parse_datetime(args["until"])
        except ValueError:
            return {"error": "since and until must be valid ISO 8601 datetime strings"}, 400

        with db.get_session() as session:
            rows, total = PlatformEventService.list_events(
                session,
                pylon_id=args.get("pylon_id"),
                event_type=args.get("event_type"),
                since=since,
                until=until,
                limit=limit,
                offset=offset,
            )

            return {
                "total": total,
                "rows": [r.to_dict() for r in rows],
            }


class API(api_tools.APIBase):
    """API resource."""

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        "administration": AdminAPI,
    }
