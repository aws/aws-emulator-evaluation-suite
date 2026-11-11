"""graphql-endpoint-cors-preflight-and-cross-origin-error-readability."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-endpoint-cors-preflight-and-cross-origin-error-readability"
GROUP = "data-plane"
SERVICES = ["appsync"]

SDL = """schema { query: Query }
type Query {
    ping: String
}
"""
APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
JS_PONG = (
    "export function request(ctx) {\n  return { payload: 'pong' };\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)
ORIGIN = "https://sim2real.example"
BAD_KEY = "da2-" + "x" * 26


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """The GraphQL endpoint answers a CORS preflight and its 200 and 401 responses both carry the
    CORS grant, so a browser can read UnauthorizedException; a bare OPTIONS is refused 404.
    """
    appsync = ctx.client("appsync")

    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-cors-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    url = (api.get("uris") or {}).get("GRAPHQL")
    assert url, f"CreateGraphqlApi exposed no GRAPHQL uri: {api.get('uris')!r}"
    appsync.start_schema_creation(apiId=api_id, definition=SDL.encode("utf-8"))
    status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=180.0, interval_s=2.0, description="schema creation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation failed: {status['status']!r} details={status.get('details')!r}"
    )
    ds_name = ctx.unique_name("ds").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))
    appsync.create_resolver(
        apiId=api_id, typeName="Query", fieldName="ping", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_PONG,
    )
    ctx.on_cleanup(lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping"))
    key = appsync.create_api_key(apiId=api_id, description="sim2real-behav cors key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=key))
    assert key != BAD_KEY, "the forged key collided with the real key"

    query = {"query": "query { ping }"}
    _poll_until(
        lambda: _request(ctx, url, "POST", {"Content-Type": "application/json", "x-api-key": key}, query),
        lambda r: r[0] == 200 and (r[2].get("data") or {}).get("ping") == "pong",
        timeout_s=180.0, interval_s=5.0, description="the resolver to answer on the live endpoint",
    )

    # A preflight returns 200, empty body, Allow-Origin '*', echoed method/headers, Max-Age 172800.
    code, hdrs, body, raw = _request(ctx, url, "OPTIONS", {
        "Origin": ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-api-key",
    })
    assert code == 200, f"the CORS preflight must succeed, got {code!r} {raw!r}"
    assert raw == "", f"a preflight response carries no body, got {raw!r}"
    assert hdrs.get("access-control-allow-origin") == "*", (
        f"preflight Access-Control-Allow-Origin must be '*', got {hdrs!r}"
    )
    assert hdrs.get("access-control-allow-methods") == "POST", (
        f"the preflight must grant the requested method POST, got "
        f"{hdrs.get('access-control-allow-methods')!r}"
    )
    allowed = {h.strip().lower() for h in hdrs.get("access-control-allow-headers", "").split(",")}
    assert {"content-type", "x-api-key"} <= allowed, (
        f"the preflight must grant the requested headers content-type and x-api-key, got "
        f"{hdrs.get('access-control-allow-headers')!r}"
    )
    assert hdrs.get("access-control-max-age") == "172800", (
        f"preflight Access-Control-Max-Age must be 172800, got {hdrs.get('access-control-max-age')!r}"
    )
    exposed = {h.strip().lower() for h in hdrs.get("access-control-expose-headers", "").split(",")}
    assert {"x-amzn-requestid", "x-amzn-errortype"} <= exposed, (
        f"the preflight must expose x-amzn-RequestId and x-amzn-ErrorType, got {exposed!r}"
    )

    # A 401 must also carry the CORS grant and expose x-amzn-ErrorType, or the browser sees only
    # an opaque network failure.
    code, hdrs, body, raw = _request(
        ctx, url, "POST", {"Content-Type": "application/json", "x-api-key": key, "Origin": ORIGIN}, query
    )
    assert code == 200 and (body.get("data") or {}).get("ping") == "pong", (
        f"the cross-origin POST must be served, got {code!r} {raw!r}"
    )
    assert hdrs.get("access-control-allow-origin") == "*", (
        f"a served cross-origin response must carry Access-Control-Allow-Origin '*', got {hdrs!r}"
    )

    code, hdrs, body, raw = _request(
        ctx, url, "POST", {"Content-Type": "application/json", "x-api-key": BAD_KEY, "Origin": ORIGIN},
        query,
    )
    assert code == 401, f"a forged key must be rejected 401, got {code!r} {raw!r}"
    errors = body.get("errors") or []
    assert errors and errors[0].get("errorType") == "UnauthorizedException", (
        f"the 401 body must name UnauthorizedException, got {raw!r}"
    )
    assert hdrs.get("access-control-allow-origin") == "*", (
        f"the 401 must ALSO carry Access-Control-Allow-Origin, or a browser cannot read the "
        f"rejection at all; headers were {hdrs!r}"
    )
    exposed = {h.strip().lower() for h in hdrs.get("access-control-expose-headers", "").split(",")}
    assert "x-amzn-errortype" in exposed, (
        f"the 401 must expose x-amzn-ErrorType to the browser, got {exposed!r}"
    )

    # An OPTIONS with no CORS request headers is not a preflight: 404 UnknownOperationException.
    code, hdrs, body, raw = _request(ctx, url, "OPTIONS", {})
    assert code == 404, f"a bare OPTIONS is not a preflight: expected 404, got {code!r} {raw!r}"
    errors = body.get("errors") or []
    assert errors and errors[0].get("errorType") == "UnknownOperationException", (
        f"a bare OPTIONS must be refused UnknownOperationException, got {raw!r}"
    )
    assert "access-control-allow-origin" not in hdrs, (
        f"a non-preflight OPTIONS must grant no CORS access, got {hdrs!r}"
    )




def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _request(ctx, url, method, headers, payload=None, timeout_s=30):
    """Raw HTTP via urllib -> (status, lowercased headers, parsed JSON body or {}, raw body)."""
    data = json.dumps(payload).encode() if payload is not None else None
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=data, method=method, headers={**headers, **route_headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, hdrs, raw = resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, hdrs, raw = exc.code, exc.headers, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {}, {"transport_error": str(exc)}, ""
    lowered = {k.lower(): v for k, v in hdrs.items()}
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {}
    return status, lowered, parsed if isinstance(parsed, dict) else {}, raw


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
