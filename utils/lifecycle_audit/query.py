#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Read / export parameters: validated once, used by both the list and the CSV export """

import datetime

TABS = ("projects", "users")

# API name -> column; anything else sorts by time
SORT_COLUMNS = {
    "time": "occurred_at",
    "occurred_at": "occurred_at",
    "event_type": "event_type",
    "project_name": "project_name",
    "project_id": "project_id",
    "user_name": "user_name",
    "user_id": "user_id",
    "actor_name": "actor_name",
    "result": "result",
}

TEXT_FILTERS = ("project_name", "user_name", "user_email")
EXACT_FILTERS = ("project_type", "result", "source")
ADMIN_ACCESS = ("granted", "revoked", "any")

DEFAULT_LIMIT = 50
MAX_LIMIT = 500
# Deeper pages are reached by narrowing the date range or filters, not by offset
MAX_OFFSET = 10000


def _truthy(value):
    return str(value).lower() in ("1", "true", "yes", "on")


def _datetime(value, name):
    if isinstance(value, datetime.datetime):
        result = value
    else:
        try:
            result = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"{name} is not an ISO-8601 date-time") from error
    if result.tzinfo is None:
        result = result.replace(tzinfo=datetime.timezone.utc)
    return result.astimezone(datetime.timezone.utc)


def _int(value, name):
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be an integer") from error


def _list(value):
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = str(value).split(",")
    return [str(item).strip() for item in items if str(item).strip()]


def parse(params):  # pylint: disable=R0912
    """ Validated parameters; ValueError on bad input

    A date range is required (partition pruning) unless all_time is set explicitly.
    """
    params = dict(params or {})
    result = {"tab": params.get("tab") or None}
    if result["tab"] is not None and result["tab"] not in TABS:
        raise ValueError(f"tab must be one of {TABS}")
    #
    if _truthy(params.get("all_time", "")):
        result["date_from"] = result["date_to"] = None
    else:
        if not params.get("date_from") or not params.get("date_to"):
            raise ValueError("date_from and date_to are required unless all_time is set")
        result["date_from"] = _datetime(params["date_from"], "date_from")
        result["date_to"] = _datetime(params["date_to"], "date_to")
        if result["date_from"] > result["date_to"]:
            raise ValueError("date_from is after date_to")
    #
    result["event_type"] = _list(params.get("event_type"))
    for name in ("project_id", "user_id"):
        result[name] = _int(params[name], name) if params.get(name) not in (None, "") else None
    for name in TEXT_FILTERS + EXACT_FILTERS:
        value = params.get(name)
        result[name] = str(value).strip() if value not in (None, "") else None
    result["actor"] = str(params["actor"]).strip() if params.get("actor") not in (None, "") else None
    result["role"] = str(params["role"]).strip() if params.get("role") not in (None, "") else None
    #
    access = params.get("admin_access")
    if access in (None, ""):
        result["admin_access"] = None
    elif access in ADMIN_ACCESS:
        result["admin_access"] = access
    else:
        raise ValueError(f"admin_access must be one of {ADMIN_ACCESS}")
    #
    imported = params.get("imported")
    result["imported"] = None if imported in (None, "") else _truthy(imported)
    result["q"] = str(params["q"]).strip().lower() if params.get("q") not in (None, "") else None
    #
    result["sort_by"] = SORT_COLUMNS.get(str(params.get("sort_by") or "time"), "occurred_at")
    result["sort_order"] = "asc" if str(params.get("sort_order", "desc")).lower() == "asc" else "desc"
    #
    limit = _int(params.get("limit", DEFAULT_LIMIT), "limit")
    result["limit"] = max(1, min(limit, MAX_LIMIT))
    result["offset"] = max(0, _int(params.get("offset", 0), "offset"))
    if result["offset"] > MAX_OFFSET:
        raise ValueError(f"offset must be at most {MAX_OFFSET}; narrow the date range or filters")
    return result
