"""graphql-deleted-api-key-refused-on-data-plane."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-deleted-api-key-refused-on-data-plane"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query }
type Query {
    guarded: String
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")

def run(ctx) -> None:
    """DeleteApiKey revokes that key on the data plane and only that key: requests bearing the
    deleted key are refused 401 UnauthorizedException with no resolved data, while a second key on
    the same API keeps resolving.
    """
    svc = ctx.client("appsync")
    api_id, url, key_a = _graphql_endpoint(ctx, svc, SDL)
    key_b = svc.create_api_key(apiId=api_id, description="sim2real-behav second key")["apiKey"]["id"]

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="guarded",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate='{"version":"2018-05-29","payload":"guarded-value"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="guarded"))

    query = "query { guarded }"

    def _resolves(key):
        return _poll_until(
            lambda: _gql(ctx, url, key, query),
            lambda res: res[0] == 200 and (res[1].get("data") or {}).get("guarded") == "guarded-value",
            timeout_s=180, interval_s=5.0,
            description="the api key to resolve the guarded field",
        )

    # Both keys are valid before anything is broken.
    _resolves(key_a)
    _resolves(key_b)

    svc.delete_api_key(apiId=api_id, id=key_a)
    assert key_a not in {k["id"] for k in svc.list_api_keys(apiId=api_id)["apiKeys"]}, (
        "expected DeleteApiKey to remove the key from ListApiKeys"
    )

    status, body, headers = _poll_until(
        lambda: _gql(ctx, url, key_a, query),
        lambda res: res[0] == 401,
        timeout_s=180, interval_s=5.0,
        description="the deleted api key to be refused by the data plane",
    )
    assert status == 401, (
        f"expected the revoked api key to be refused 401, got status={status} body={body!r}"
    )
    error_header = headers.get("x-amzn-ErrorType") or headers.get("x-amzn-errortype") or ""
    surfaced_types = {e.get("errorType") for e in (body.get("errors") or [])}
    assert "UnauthorizedException" in error_header or "UnauthorizedException" in surfaced_types, (
        f"expected UnauthorizedException to be surfaced, got header={error_header!r} body={body!r}"
    )
    assert body.get("data") is None, (
        f"expected NO resolved data for a revoked key, got {body.get('data')!r}"
    )

    # Control: revoking one key must not revoke the API or its other keys.
    status, body, _h = _gql(ctx, url, key_b, query)
    assert status == 200 and (body.get("data") or {}).get("guarded") == "guarded-value", (
        f"expected the second, still-valid api key to keep resolving after key A was deleted, "
        f"got status={status} body={body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
