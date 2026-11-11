"""graphql-append-error-partial-data-and-nonnull-propagation."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-append-error-partial-data-and-nonnull-propagation"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query }
type Query {
    partial: String
    widget: Widget
}
type Widget {
    id: ID!
    mandatory: String!
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")

def run(ctx) -> None:
    """$util.appendError yields data AND an errors entry (partial success), while an error on a
    ``String!`` field nulls its nearest nullable parent (``data.widget`` is null) with
    ``errors[0].path`` naming the nested field: the GraphQL-spec error semantics.
    """
    svc = ctx.client("appsync")
    api_id, url, api_key = _graphql_endpoint(ctx, svc, SDL)

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="partial",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate='{"version":"2018-05-29","payload":"partial-value"}',
        responseMappingTemplate=(
            '$util.appendError("partial-oops", "PartialErrorType")\n'
            "$util.toJson($ctx.result)"
        ),
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="partial"))

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="widget",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate='{"version":"2018-05-29","payload":{"id":"w-1"}}',
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="widget"))

    svc.create_resolver(
        apiId=api_id, typeName="Widget", fieldName="mandatory",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate='{"version":"2018-05-29","payload":{}}',
        responseMappingTemplate='$util.error("mandatory-boom", "MandatoryBoomType")',
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Widget", fieldName="mandatory"))

    def _run(query):
        def _attempt():
            return _gql(ctx, url, api_key, query)

        return _poll_until(
            _attempt,
            lambda res: res[0] is not None and "data" in res[1] and bool(res[1].get("errors")),
            timeout_s=180, interval_s=5.0,
            description="the GraphQL endpoint to execute and return an errors envelope",
        )

    # 1. appendError: the field still resolves, and the error rides alongside it.
    status, body, _h = _run("query { partial }")
    assert status == 200, f"expected HTTP 200 for an appendError response, got {status} body={body!r}"
    assert body["data"].get("partial") == "partial-value", (
        f"expected $util.appendError to preserve the resolved value (partial success), "
        f"got data={body.get('data')!r} errors={body.get('errors')!r}"
    )
    errors = body["errors"]
    assert len(errors) == 1, f"expected exactly one appended error, got {errors!r}"
    assert errors[0].get("errorType") == "PartialErrorType", (
        f"expected the appended errorType verbatim, got {errors[0]!r}"
    )
    assert errors[0].get("message") == "partial-oops", (
        f"expected the appended message verbatim, got {errors[0]!r}"
    )
    assert errors[0].get("path") == ["partial"], (
        f"expected errors[0].path to name the field, got {errors[0].get('path')!r}"
    )

    # 2. Non-null propagation: the failure on Widget.mandatory (String!) nulls the whole widget.
    status, body, _h = _run("query { widget { id mandatory } }")
    assert status == 200, f"expected HTTP 200 for a field error, got {status} body={body!r}"
    assert body["data"].get("widget", "MISSING") is None, (
        f"expected the null from the failed non-null field to propagate up to the nullable "
        f"parent (data.widget == null), got {body['data']!r}"
    )
    errors = body["errors"]
    assert len(errors) == 1, f"expected exactly one error for the failing nested field, got {errors!r}"
    assert errors[0].get("errorType") == "MandatoryBoomType", (
        f"expected the nested resolver's errorType, got {errors[0]!r}"
    )
    assert errors[0].get("path") == ["widget", "mandatory"], (
        f"expected errors[0].path to be the full response path of the failing non-null field, "
        f"got {errors[0].get('path')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
