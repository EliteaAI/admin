#!/usr/bin/python3
# coding=utf-8

""" API """
import flask

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth, api_tools  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903,C0115
    @auth.decorators.check_api({
        "permissions": ["admin.auth.users"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def put(self, user_id: int, **kwargs):
        """ Toggle user suspended state """
        suspended = flask.request.json.get("suspended")
        if suspended is None:
            return {"error": "suspended field is required"}, 400
        #
        try:
            auth.update_user(id_=user_id, suspended=bool(suspended))
        except RuntimeError as e:
            return {"error": str(e)}, 404
        #
        return {"id": user_id, "suspended": bool(suspended)}, 200


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>/<int:user_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
