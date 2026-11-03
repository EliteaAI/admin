""" Group nesting from Microsoft Graph (#5202): Entra SCIM sends only direct members.

Needs an Entra app with the GroupMember.Read.All application permission (admin consent); its client id,
secret and authority come from an OAuth App of the Configurations plugin.
"""
import requests

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPE = "https://graph.microsoft.com/.default"
TIMEOUT_S = 20
MAX_PAGES = 50


def child_group_ids(pages) -> list:
    """ Ids of the groups in Graph member pages (members/microsoft.graph.group) """
    ids = []
    for page in pages:
        for item in (page or {}).get("value") or []:
            kind = item.get("@odata.type")
            if item.get("id") and kind in (None, "#microsoft.graph.group"):
                ids.append(item["id"])
    return ids


def app_token(token_endpoint: str, client_id: str, client_secret: str) -> str:
    response = requests.post(token_endpoint, timeout=TIMEOUT_S, data={
        "grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret,
        "scope": SCOPE,
    })
    body = response.json()
    if not body.get("access_token"):
        raise RuntimeError(f"Graph token refused: {body.get('error') or response.status_code}")
    return body["access_token"]


def _pages(session, url):
    for _ in range(MAX_PAGES):
        response = session.get(url, timeout=TIMEOUT_S)
        if response.status_code == 404:
            return
        if response.status_code >= 400:
            raise RuntimeError(f"Graph {response.status_code}: {response.text[:200]}")
        page = response.json()
        yield page
        url = page.get("@odata.nextLink")
        if not url:
            return


def fetcher(token: str):
    """ fetch_children([external ids]) -> {parent: [child group ids]} for ProjectSync.pull_edges """

    def fetch_children(external_ids):
        session = requests.Session()
        session.headers["Authorization"] = f"Bearer {token}"
        edges = {}
        for group_id in external_ids:
            url = f"{GRAPH}/groups/{group_id}/members/microsoft.graph.group?$select=id"
            children = child_group_ids(_pages(session, url))
            if children:
                edges[group_id] = children
        return edges

    return fetch_children
