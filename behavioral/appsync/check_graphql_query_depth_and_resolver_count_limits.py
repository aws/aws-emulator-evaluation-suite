"""graphql-query-depth-and-resolver-count-limits."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-query-depth-and-resolver-count-limits"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query }
type Query {
    top: Level1
    sibling: String
}
type Level1 {
    name: String
    nested: Level2
}
type Level2 {
    leaf: String
}
"""

SHALLOW = "query { top { name } }"
DEEP = "query { top { nested { leaf } } }"
TWO_RESOLVERS = "query { top { name } sibling }"

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
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")

def run(ctx) -> None:
    """queryDepthLimit and resolverCountLimit cut an offending query at the limit (HTTP 200, a typed
    QueryDepthLimitReached / ResolverExecutionLimitReached error, only the field beyond it null)
    while a compliant query resolves, and lifting the limit restores the full result.
    """
    svc = ctx.client("appsync")
    api_id, url, api_key = _graphql_endpoint(ctx, svc, SDL)
    api_name = svc.get_graphql_api(apiId=api_id)["graphqlApi"]["name"]

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="top",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate=(
            '{"version":"2018-05-29","payload":'
            '{"name":"l1","nested":{"leaf":"deep"}}}'
        ),
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="top"))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="sibling",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate='{"version":"2018-05-29","payload":"sibling-value"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="sibling"))

    def _set_limits(depth, resolvers):
        # UpdateGraphqlApi is a full replace: the identity fields must be re-supplied.
        updated = svc.update_graphql_api(
            apiId=api_id, name=api_name, authenticationType="API_KEY",
            queryDepthLimit=depth, resolverCountLimit=resolvers,
        )["graphqlApi"]
        assert updated["queryDepthLimit"] == depth, updated
        assert updated["resolverCountLimit"] == resolvers, updated

    def _resolves(query, description):
        return _poll_until(
            lambda: _gql(ctx, url, api_key, query),
            lambda res: res[0] == 200
            and isinstance(res[1].get("data"), dict)
            and not res[1].get("errors"),
            timeout_s=180, interval_s=5.0, description=description,
        )

    def _refused(query, error_type, message_text, nulled_path, description):
        """Assert a limit violation the way real AppSync reports it: a 200 GraphQL envelope
        whose errors array carries the TYPED limit error, and whose data has the offending
        field -- and only the offending field -- nulled out.

        A limit violation is NOT a request error.
        AppSync executes the query up to the limit and reports the cut as a typed error
        alongside PARTIAL data: with queryDepthLimit=2, ``query { top { nested { leaf } } }``
        answers 200 with data {'top': {'nested': {'leaf': None}}} plus a single error
        {errorType: 'QueryDepthLimitReached', message: 'Query depth limit reached.', path: [],
        locations: [], data: None, errorInfo: None}. So "data is null" is the wrong assertion;
        the discriminating facts are the errorType, the exact message, and WHICH leaf got
        nulled while its ancestors still resolved.
        """
        status, body, _h = _poll_until(
            lambda: _gql(ctx, url, api_key, query),
            lambda res: res[0] is not None and bool(res[1].get("errors")),
            timeout_s=180, interval_s=5.0, description=description,
        )
        assert status == 200, (
            f"{description}: a limit violation is reported inside the GraphQL envelope, so the "
            f"HTTP status stays 200; got status={status} body={body!r}"
        )
        errors = body["errors"]
        assert len(errors) == 1, (
            f"{description}: expected exactly one limit error, got {errors!r}"
        )
        err = errors[0]
        assert err.get("errorType") == error_type, (
            f"{description}: expected the typed AppSync error {error_type!r}, got "
            f"{err.get('errorType')!r} ({err!r})"
        )
        assert err.get("message") == message_text, (
            f"{description}: expected message {message_text!r}, got {err.get('message')!r}"
        )
        assert err.get("path") == [], (
            f"{description}: a limit error is raised against the operation as a whole, so path "
            f"must be the empty list, got {err.get('path')!r}"
        )
        # PARTIAL data, with exactly the field beyond the limit nulled: walk to it and assert
        # both that it is null and that everything on the way there resolved.
        node = body.get("data")
        assert isinstance(node, dict), (
            f"{description}: AppSync returns the partially resolved data alongside the limit "
            f"error, got data={node!r}"
        )
        for key in nulled_path[:-1]:
            assert isinstance(node.get(key), dict), (
                f"{description}: fields inside the limit must still resolve, but {key!r} is "
                f"{node.get(key)!r} in {body['data']!r}"
            )
            node = node[key]
        leaf = nulled_path[-1]
        assert leaf in node, (
            f"{description}: expected the refused field {leaf!r} to be present-and-null in the "
            f"partial data, got {node!r}"
        )
        assert node[leaf] is None, (
            f"{description}: the field beyond the limit must resolve to null, got "
            f"{node[leaf]!r}; the limit was not enforced"
        )
        return body

    # Phase A -- query depth. Depth 2 is allowed; the depth-3 leaf is cut.
    _set_limits(2, 0)
    _refused(
        DEEP, "QueryDepthLimitReached", "Query depth limit reached.",
        ["top", "nested", "leaf"],
        "queryDepthLimit=2 to be enforced on the data plane",
    )
    status, body, _h = _resolves(SHALLOW, "the depth-2 query to keep resolving under queryDepthLimit=2")
    assert body["data"]["top"]["name"] == "l1", body

    # Phase B -- resolver count. The first resolver runs; the second is cut. Note the different
    # errorType and message: the two limits are reported as distinct typed errors, not one
    # generic "limit" refusal.
    _set_limits(0, 1)
    cut = _refused(
        TWO_RESOLVERS, "ResolverExecutionLimitReached", "Resolver invocation limit reached.",
        ["sibling"],
        "resolverCountLimit=1 to be enforced on the data plane",
    )
    assert cut["data"]["top"]["name"] == "l1", (
        f"resolverCountLimit=1 must cut the SECOND resolver only: the first one's data must "
        f"still be in the response, got {cut['data']!r}"
    )
    status, body, _h = _resolves(SHALLOW, "the single-resolver query to keep resolving under resolverCountLimit=1")
    assert body["data"]["top"]["name"] == "l1", body

    # Phase C -- lift both limits; the previously refused queries must resolve again.
    _set_limits(0, 0)
    status, body, _h = _resolves(DEEP, "the deep query to resolve again once queryDepthLimit is lifted")
    assert body["data"]["top"]["nested"]["leaf"] == "deep", body
    status, body, _h = _resolves(
        TWO_RESOLVERS, "the two-resolver query to resolve again once resolverCountLimit is lifted"
    )
    assert body["data"]["sibling"] == "sibling-value", body


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
