"""graphql-resolver-error-returns-http-200-with-errors-envelope."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-resolver-error-returns-http-200-with-errors-envelope"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query }
type Query {
    ok: String
    failing: String
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
        tags=api_kwargs.pop("tags", {"sim2real:managed": "true", "sim2real:check": CHECK}),
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
    """A ``$util.error`` resolver error is delivered as HTTP 200 with ``errors[0]`` carrying
    errorType / message / path / locations, and only the failing field null while sibling fields
    still resolve, not as a 4xx or an aborted request.
    """
    svc = ctx.client("appsync")
    api_id, url, api_key = _graphql_endpoint(ctx, svc, SDL)

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="ok",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate='{"version":"2018-05-29","payload":"ok-value"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="ok"))

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="failing",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate='{"version":"2018-05-29","payload":{}}',
        responseMappingTemplate='$util.error("resolver-boom", "ResolverBoomType")',
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="failing"))

    query = "query { ok failing }"

    def _attempt():
        return _gql(ctx, url, api_key, query)

    def _executed(res):
        status, body, _hdrs = res
        # The request has reached execution once the body carries BOTH halves of the
        # envelope; a warming endpoint answers 401/5xx or nothing at all.
        return status is not None and isinstance(body, dict) and "data" in body and bool(body.get("errors"))

    status, body, _hdrs = _poll_until(
        _attempt, _executed, timeout_s=180, interval_s=5.0,
        description="the GraphQL endpoint to execute the query and return an errors envelope",
    )

    assert status == 200, (
        f"a resolver error must be reported as HTTP 200 with a GraphQL errors array, "
        f"not a transport error; got status={status} body={body!r}"
    )

    errors = body.get("errors")
    assert isinstance(errors, list) and len(errors) == 1, (
        f"expected exactly one GraphQL error for the single failing field, got {errors!r}"
    )
    err = errors[0]
    assert err.get("errorType") == "ResolverBoomType", (
        f"expected the errorType passed to $util.error to be surfaced verbatim, got {err!r}"
    )
    assert err.get("message") == "resolver-boom", (
        f"expected the message passed to $util.error to be surfaced verbatim, got {err!r}"
    )
    assert err.get("path") == ["failing"], (
        f"expected errors[0].path to name the failing response path, got {err.get('path')!r}"
    )
    locations = err.get("locations")
    assert isinstance(locations, list) and locations, (
        f"expected errors[0].locations to point back into the query document, got {locations!r}"
    )
    assert all(
        isinstance(loc, dict) and isinstance(loc.get("line"), int) and isinstance(loc.get("column"), int)
        for loc in locations
    ), f"expected every location to carry integer line/column, got {locations!r}"

    data = body.get("data")
    assert isinstance(data, dict), f"expected a data object alongside the errors, got {data!r}"
    assert data.get("failing", "MISSING") is None, (
        f"expected the failing field to be present-and-null in data, got {data!r}"
    )
    # Control: the error must NOT abort the rest of the selection set.
    assert data.get("ok") == "ok-value", (
        f"expected the sibling field to still resolve despite the error on 'failing', got {data!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
