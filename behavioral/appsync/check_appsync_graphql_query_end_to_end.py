"""appsync-graphql-query-end-to-end."""

from __future__ import annotations

import time
import re

from behavioral_harness import tags


def _sanitize(name):
    """AppSync data source/function names must match ^[_A-Za-z][_0-9A-Za-z]*$."""
    cleaned = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not cleaned or not re.match(r"[_A-Za-z]", cleaned[0]):
        cleaned = "n_" + cleaned
    return cleaned


def _poll_until(
    probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


CHECK = "appsync-graphql-query-end-to-end"
GROUP = "end-to-end"
SERVICES = ["appsync"]

# Prefix of the failure detail raised when the live GraphQL endpoint does not serve the query, so
# the failure reads as a data-plane miss rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
DEFAULT_SCHEMA = """schema {
    query: Query
}

type Query {
    getWidget(id: ID!): Widget
    getWidget2(id: ID!): Widget
}

type Widget {
    id: ID!
    name: String
}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A GraphQL query POSTed with an API key to the live GRAPHQL URI of an API with a NONE data
    source and a UNIT resolver returns the resolver's data over the wire: the endpoint itself
    executes queries, not just EvaluateCode/EvaluateMappingTemplate.
    """
    svc = ctx.client("appsync")

    import requests

    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    graphql_url = api.get("uris", {}).get("GRAPHQL")
    if not graphql_url:
        raise AssertionError("GraphQL API exposed no GRAPHQL endpoint URI")

    svc.start_schema_creation(apiId=api_id, definition=DEFAULT_SCHEMA)
    _sc = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=60,
        interval_s=1.5,
        description="schema creation",
    )
    if _sc.get("status") == "FAILED":
        raise AssertionError(f"schema creation failed: {_sc.get('details')}")
    ds = svc.create_data_source(
        apiId=api_id, name=_sanitize(ctx.unique_name("sim2real-behav-ds_")), type="NONE"
    )["dataSource"]

    # NONE data source: the request template's payload becomes $ctx.result, so
    # the resolver echoes a fixed name plus the queried id — resolved data with
    # no external backend.
    request_template = (
        '{"version":"2018-05-29","payload":'
        '{"id": $util.toJson($context.arguments.id),"name":"resolved-widget"}}'
    )
    svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget",
        kind="UNIT",
        dataSourceName=ds["name"],
        requestMappingTemplate=request_template,
        responseMappingTemplate="$util.toJson($context.result)",
    )

    api_key = svc.create_api_key(apiId=api_id, description="sim2real-e2e")["apiKey"][
        "id"
    ]

    query = {
        "query": "query($id: ID!){ getWidget(id: $id){ id name } }",
        "variables": {"id": "w-1"},
    }
    headers = {"x-api-key": api_key, "Content-Type": "application/json"}

    last_exc: list[Exception] = []

    def post():
        try:
            routed_url, route_headers = ctx.endpoint_route(graphql_url)
            return requests.post(routed_url, json=query, headers={**headers, **route_headers}, timeout=15)
        except (requests.ConnectionError, requests.Timeout) as exc:  # transient during API-key / endpoint warmup
            # Recorded rather than discarded: if the poll budget expires, this is the only
            # evidence of why, and `Last result: None` on its own names no cause.
            last_exc.append(exc)
            return None

    def resolved(r) -> bool:
        if r is None or r.status_code != 200:
            return False
        try:
            body = r.json()
        except Exception:  # noqa: BLE001
            return False
        return bool(body.get("data") and body["data"].get("getWidget"))

    # Marked: the GraphQL URL comes from the API the target just created, and the schema and
    # resolver are in place, so 120s of not resolving a query is a data-plane failure. The prefix
    # makes a transport error ("Connection refused", "Read timed out") read as that, not as a
    # connection problem.
    try:
        resp = _poll_until(
            post,
            resolved,
            timeout_s=120,
            interval_s=5,
            description="GraphQL query resolving data over the live endpoint",
        )
    except AssertionError as exc:
        tail = (
            f" (last transport error: {type(last_exc[-1]).__name__}: {last_exc[-1]})"
            if last_exc
            else ""
        )
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}{tail}") from exc
    body = resp.json()
    assert not body.get("errors"), f"GraphQL errors: {body.get('errors')}"
    widget = body["data"]["getWidget"]
    assert widget["id"] == "w-1", widget
    assert widget["name"] == "resolved-widget", widget


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
