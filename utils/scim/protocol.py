""" SCIM 2.0 (RFC 7643/7644) subset the Entra provisioning service uses: filters, PATCH, errors, lists.

Pure functions: no DB, no pylon.
"""
import re
import unicodedata

USER = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
SERVICE_PROVIDER_CONFIG = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"

CONTENT_TYPE = "application/scim+json"
FILTER_ATTRIBUTES = ("username", "displayname", "externalid")
PATCH_OPS = ("add", "replace", "remove")
MAX_COUNT = 200
DEFAULT_COUNT = 100

_FILTER_RE = re.compile(r'^\s*(\w+)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$', re.IGNORECASE)
_MEMBER_PATH_RE = re.compile(r'^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$', re.IGNORECASE)


class ScimError(Exception):
    """ An error answered in the SCIM error format """

    def __init__(self, status: int, detail: str, scim_type: str = None):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type

    def body(self) -> dict:
        body = {"schemas": [ERROR], "status": str(self.status)}
        if self.scim_type:
            body["scimType"] = self.scim_type
        body["detail"] = self.detail
        return body


def parse_filter(text):
    """ (attribute in lower case, value) for 'attr eq "value"', None for no filter """
    if not text:
        return None
    match = _FILTER_RE.match(text)
    if not match or match.group(1).lower() not in FILTER_ATTRIBUTES:
        raise ScimError(400, f"Unsupported filter: {text[:100]}", "invalidFilter")
    return match.group(1).lower(), re.sub(r'\\(.)', r'\1', match.group(2))


def parse_patch(body) -> list:
    """ [(op in lower case, path or None, value)] of a PatchOp request """
    if not isinstance(body, dict) or PATCH_OP not in (body.get("schemas") or []):
        raise ScimError(400, "A PatchOp request is required", "invalidSyntax")
    operations = body.get("Operations")
    if not isinstance(operations, list) or not operations:
        raise ScimError(400, "Operations must be a non-empty list", "invalidSyntax")
    result = []
    for operation in operations:
        op = str((operation or {}).get("op", "")).lower()
        if op not in PATCH_OPS:
            raise ScimError(400, f"Unsupported op: {op[:20]}", "invalidSyntax")
        result.append((op, operation.get("path"), operation.get("value")))
    return result


def bool_value(value) -> bool:
    """ Entra sends booleans as "True"/"False" strings in PATCH """
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise ScimError(400, "A boolean value is required", "invalidValue")


def member_filter_value(path):
    """ The member id of a 'members[value eq "<id>"]' path, else None """
    match = _MEMBER_PATH_RE.match(path or "")
    return match.group(1) if match else None


def primary_email(resource: dict):
    """ The primary (else first) email, else userName when it is one; lower case """
    emails = [e for e in (resource.get("emails") or []) if isinstance(e, dict) and e.get("value")]
    chosen = next((e for e in emails if e.get("primary") in (True, "True", "true")), emails[0] if emails else None)
    value = chosen["value"] if chosen else resource.get("userName")
    if not value or "@" not in value:
        return None
    return value.strip().lower()


PROJECT_NAME_MAX = 120
PROJECT_NAME_FALLBACK = "scim-group"
PERSONAL_PROJECT_PREFIX = "project_user_"
_NAME_ALLOWED = set(" -_.()&")


def sanitize_project_name(name) -> str:
    """ A group name as a project name: letters, digits, spaces and -_.()& only, one space, at most 120 """
    text = unicodedata.normalize("NFC", name or "")
    out = []
    for ch in text:
        if ch.isspace():
            out.append(" ")
        elif unicodedata.category(ch).startswith("C"):
            continue
        elif ch.isalnum() or ch in _NAME_ALLOWED:
            out.append(ch)
        else:
            out.append("-")
    result = re.sub(r" +", " ", "".join(out))
    result = re.sub(r"-+( ?-+)*", "-", result)
    result = result.strip(" -")[:PROJECT_NAME_MAX].strip(" -")
    if not result:
        return PROJECT_NAME_FALLBACK
    if result.lower().startswith(PERSONAL_PROJECT_PREFIX):
        result = ("group-" + result)[:PROJECT_NAME_MAX]
    return result


def project_name_for(group_name) -> str:
    """ The project name of a group: its sanitized name, nothing added (names follow the IdP) """
    return sanitize_project_name(group_name)


def page_args(args) -> tuple:
    """ (startIndex >= 1, count in 0..MAX_COUNT) """
    try:
        start = int(args.get("startIndex", 1))
        count = int(args.get("count", DEFAULT_COUNT))
    except (TypeError, ValueError) as exc:
        raise ScimError(400, "startIndex and count must be integers", "invalidValue") from exc
    return max(start, 1), min(max(count, 0), MAX_COUNT)


def list_response(resources: list, total: int, start_index: int = 1) -> dict:
    return {
        "schemas": [LIST_RESPONSE], "totalResults": total, "startIndex": start_index,
        "itemsPerPage": len(resources), "Resources": resources,
    }


def service_provider_config() -> dict:
    return {
        "schemas": [SERVICE_PROVIDER_CONFIG],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_COUNT},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken", "name": "OAuth Bearer Token",
            "description": "Authentication with the SCIM token issued in ELITEA administration",
        }],
    }


def resource_types(base_url: str) -> list:
    return [
        {"schemas": [RESOURCE_TYPE], "id": "User", "name": "User", "endpoint": "/Users", "schema": USER,
         "meta": {"resourceType": "ResourceType", "location": f"{base_url}/ResourceTypes/User"}},
        {"schemas": [RESOURCE_TYPE], "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": GROUP,
         "meta": {"resourceType": "ResourceType", "location": f"{base_url}/ResourceTypes/Group"}},
    ]


def schemas() -> list:
    def attribute(name, kind="string", multi=False, **extra):
        return {"name": name, "type": kind, "multiValued": multi, "required": extra.pop("required", False),
                "mutability": "readWrite", "returned": "default", "uniqueness": extra.pop("uniqueness", "none"),
                **extra}
    return [
        {"schemas": [SCHEMA], "id": USER, "name": "User", "attributes": [
            attribute("userName", required=True, uniqueness="server"), attribute("displayName"),
            attribute("active", "boolean"), attribute("externalId"),
            attribute("emails", "complex", True, subAttributes=[
                attribute("value"), attribute("type"), attribute("primary", "boolean")]),
        ]},
        {"schemas": [SCHEMA], "id": GROUP, "name": "Group", "attributes": [
            attribute("displayName", required=True, uniqueness="server"), attribute("externalId"),
            attribute("members", "complex", True, subAttributes=[attribute("value"), attribute("display")]),
        ]},
    ]
