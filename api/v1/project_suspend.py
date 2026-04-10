#!/usr/bin/python3
# coding=utf-8

""" API """
import flask

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth, api_tools, db  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903,C0115
    @auth.decorators.check_api({
        "permissions": ["projects.projects.projects.edit"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def put(self, project_id: int, **kwargs):
        """ Toggle project suspended state """
        from plugins.projects.models.project import Project

        suspended = flask.request.json.get("suspended")
        if suspended is None:
            return {"error": "suspended field is required"}, 400
        #
        with db.with_project_schema_session(None) as session:
            project = session.query(Project).where(
                Project.id == project_id,
            ).first()
            if not project:
                return {"error": "Project not found"}, 404
            project.suspended = bool(suspended)
            session.commit()
            return {"id": project.id, "suspended": project.suspended}, 200


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>/<int:project_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
