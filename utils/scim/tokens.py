""" SCIM bearer tokens (#5202): issued once, stored as a hash, verified by the auth plugin's bearer hook """
import hashlib
import secrets

PREFIX = "scim1."


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate() -> tuple:
    """ (token, its hash, its last 4 characters) """
    token = PREFIX + secrets.token_urlsafe(32)
    return token, hash_token(token), token[-4:]


def _refusal(status, code, message):
    return {"ok": False, "status": status, "code": code, "message": message}


def make_verifier(verify, service_user_id, path_prefix: str):
    """ verifier(token, environ) for auth.register_bearer_verifier: a SCIM token acts as the
        provisioning service user, and only on the SCIM API """

    def verifier(token, environ):
        if not (environ.get("PATH_INFO") or "").startswith(path_prefix):
            return _refusal(403, "SCIM_TOKEN_SCOPE", "A SCIM token can only be used on the SCIM API.")
        if not verify(token):
            return _refusal(401, "SCIM_TOKEN_INVALID", "The SCIM token is not valid.")
        user_id = service_user_id()
        if not user_id:
            return _refusal(503, "SCIM_UNAVAILABLE", "SCIM provisioning is not available.")
        return {"ok": True, "user_id": user_id}

    return verifier
