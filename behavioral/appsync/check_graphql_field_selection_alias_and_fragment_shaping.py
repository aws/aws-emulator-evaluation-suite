"""graphql-field-selection-alias-and-fragment-shaping."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-field-selection-alias-and-fragment-shaping"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query }
type Query {
    widget(id: ID!): Widget
}
type Widget {
    id: ID!
    name: String
    colour: String
}
"""

# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """A unique name with NO hyphens -- AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*``."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST a JSON body with stdlib urllib -> (status, parsed_body, headers).

    No third-party HTTP client: the GraphQL data plane is plain HTTPS, so urllib is enough.
    A transport-level failure returns status None so callers can keep polling a warming
    endpoint instead of failing on the first DNS/TLS miss.
    """
    data = json.dumps(payload).encode()
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=data, method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw, hdrs = resp.status, resp.read().decode(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        status, raw, hdrs = exc.code, exc.read().decode(errors="replace"), dict(exc.headers)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}, {}
    try:
        return status, (json.loads(raw) if raw else {}), hdrs
    except ValueError:
        return status, {"raw": raw}, hdrs


def _gql(ctx, url, api_key, query, variables=None):
    payload = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    return _post_json(ctx, url, {"x-api-key": api_key}, payload)


def _graphql_endpoint(ctx, svc, sdl, **api_kwargs):
    """Create an API_KEY GraphQL API + active schema + api key -> (api_id, graphql_url, api_key)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType=api_kwargs.pop("authenticationType", "API_KEY"),
        tags={"sim2real-behav": "graphql-field-selection-alias-and-fragment-shaping"},
        **api_kwargs,
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    url = (api.get("uris") or {}).get("GRAPHQL")
    if not url:
        raise AssertionError("GraphQL API exposed no GRAPHQL endpoint URI")
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=120, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal state",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: status={status['status']!r} details={status.get('details')!r}"
    )
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav graphql key")["apiKey"]["id"]
    return api_id, url, key


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The response is shaped by the selection set, not the resolver payload: unrequested fields are
    absent, aliases yield independent keys with their own arguments, a fragment spread expands and
    ``__typename`` resolves, as typed clients key off the exact shape.
    """
    svc = ctx.client("appsync")
    api_id, url, api_key = _graphql_endpoint(ctx, svc, SDL)

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="widget",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate=(
            '{"version":"2018-05-29","payload":{'
            '"id":$util.toJson($ctx.args.id),'
            '"name":"widget-name",'
            '"colour":"blue"}}'
        ),
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="widget"))

    def _run(query, variables=None):
        def _attempt():
            return _gql(ctx, url, api_key, query, variables)

        def _ok(res):
            status, body, _h = res
            return status == 200 and isinstance(body.get("data"), dict) and not body.get("errors")

        status, body, _h = _poll_until(
            _attempt, _ok, timeout_s=180, interval_s=5.0,
            description="the GraphQL endpoint to resolve the query cleanly",
        )
        assert status == 200, f"expected HTTP 200, got {status} body={body!r}"
        assert not body.get("errors"), f"unexpected GraphQL errors: {body.get('errors')!r}"
        return body["data"]

    # 1. Selection pruning: only `id` was requested, so only `id` may come back.
    data = _run('query { widget(id: "w-1") { id } }')
    assert data["widget"] == {"id": "w-1"}, (
        f"expected the response to be pruned to the requested field set, got {data['widget']!r} "
        f"(the resolver payload also carried name/colour, which must NOT appear)"
    )

    # 2. Aliases bind their own arguments; a fragment spread expands; sibling selections differ.
    data = _run(
        "query Q($a: ID!, $b: ID!) {\n"
        "  first: widget(id: $a) { ...F }\n"
        "  second: widget(id: $b) { id colour }\n"
        "}\n"
        "fragment F on Widget { id name }\n",
        {"a": "w-a", "b": "w-b"},
    )
    assert set(data) == {"first", "second"}, (
        f"expected exactly the two aliases as top-level keys, got {sorted(data)}"
    )
    assert data["first"] == {"id": "w-a", "name": "widget-name"}, (
        f"expected the fragment spread to expand to id+name for alias 'first', got {data['first']!r}"
    )
    assert data["second"] == {"id": "w-b", "colour": "blue"}, (
        f"expected alias 'second' to bind its own id argument and select id+colour only, "
        f"got {data['second']!r}"
    )

    # 3. The __typename meta-field resolves to the concrete object type.
    data = _run('query { widget(id: "w-2") { __typename id } }')
    assert data["widget"] == {"__typename": "Widget", "id": "w-2"}, (
        f"expected __typename to resolve to the schema type name alongside the selected field, "
        f"got {data['widget']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
