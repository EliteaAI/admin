#!/usr/bin/python3
# coding=utf-8

"""Platform status API endpoint for querying pylon lifecycle events."""

import flask

from pylon.core.tools import log

from tools import auth, db
from tools import api_tools, register_openapi

from ...services.platform_status import PlatformStatusService


class AdminAPI(api_tools.APIModeHandler):
    """Platform status API handler."""

    @register_openapi(
        name="List Platform Status Events",
        description="Query platform lifecycle events (restarts, reloads).",
        parameters=[
            {"name": "pylon_id", "in": "query", "schema": {"type": "string"},
             "description": "Filter by pylon identifier."},
            {"name": "event_type", "in": "query", "schema": {"type": "string"},
             "description": "Filter by event type (restart, reload)."},
            {"name": "trigger", "in": "query", "schema": {"type": "string"},
             "description": "Filter by trigger (ui, api, unplanned)."},
            {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50},
             "description": "Maximum number of results to return."},
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
        """List platform status events."""
        args = flask.request.args

        with db.get_session() as session:
            rows, total = PlatformStatusService.list_events(
                session,
                pylon_id=args.get("pylon_id"),
                event_type=args.get("event_type"),
                trigger=args.get("trigger"),
                limit=int(args.get("limit", 50)),
                offset=int(args.get("offset", 0)),
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
