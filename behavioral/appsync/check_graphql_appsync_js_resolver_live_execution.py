"""graphql-appsync-js-resolver-live-execution."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-appsync-js-resolver-live-execution"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query }
type Query {
    jsEcho(id: ID!): String
    jsEarly: String
    jsFail: String
}
"""

JS_ECHO = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return { payload: { echoed: `js-${ctx.args.id}` } };
}

export function response(ctx) {
  return ctx.result.echoed;
}
"""

JS_EARLY = """import { runtime } from '@aws-appsync/utils';

export function request(ctx) {
  runtime.earlyReturn('early-return-value');
  return { payload: {} };
}

export function response(ctx) {
  return `response-handler-ran:${ctx.result}`;
}
"""

JS_FAIL = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return { payload: {} };
}

export function response(ctx) {
  util.error('js-boom', 'JsErrorType');
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}

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
    """APPSYNC_JS resolvers compose in one live request: ``ctx.args`` mapping resolves,
    ``runtime.earlyReturn`` bypasses the data source and response handler, and ``util.error``
    surfaces as a GraphQL errorType with the other fields unaffected.
    """
    svc = ctx.client("appsync")
    api_id, url, api_key = _graphql_endpoint(ctx, svc, SDL)

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))

    for field, code in (("jsEcho", JS_ECHO), ("jsEarly", JS_EARLY), ("jsFail", JS_FAIL)):
        svc.create_resolver(
            apiId=api_id, typeName="Query", fieldName=field,
            kind="UNIT", dataSourceName=ds["name"],
            runtime=APPSYNC_JS, code=code,
        )
        ctx.on_cleanup(
            lambda _f=field: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName=_f)
        )

    query = 'query { jsEcho(id: "x1") jsEarly jsFail }'

    status, body, _h = _poll_until(
        lambda: _gql(ctx, url, api_key, query),
        lambda res: res[0] is not None and isinstance(res[1].get("data"), dict) and bool(res[1].get("errors")),
        timeout_s=180, interval_s=5.0,
        description="the APPSYNC_JS resolvers to execute on the live endpoint",
    )
    assert status == 200, f"expected HTTP 200 for JS field execution, got {status} body={body!r}"
    data = body["data"]

    assert data.get("jsEcho") == "js-x1", (
        f"expected the JS request handler to read ctx.args and the response handler to map "
        f"ctx.result, got {data.get('jsEcho')!r}"
    )
    assert data.get("jsEarly") == "early-return-value", (
        f"expected runtime.earlyReturn to return its value directly, got {data.get('jsEarly')!r}"
    )
    assert "response-handler-ran" not in str(data.get("jsEarly")), (
        f"expected runtime.earlyReturn to SKIP the response handler, but its marker is present: "
        f"{data.get('jsEarly')!r}"
    )
    assert data.get("jsFail", "MISSING") is None, (
        f"expected the util.error field to be present-and-null, got {data!r}"
    )

    errors = body["errors"]
    assert len(errors) == 1, f"expected exactly one error, from jsFail, got {errors!r}"
    assert errors[0].get("errorType") == "JsErrorType", (
        f"expected util.error's errorType from the JS runtime, got {errors[0]!r}"
    )
    assert errors[0].get("message") == "js-boom", (
        f"expected util.error's message from the JS runtime, got {errors[0]!r}"
    )
    assert errors[0].get("path") == ["jsFail"], (
        f"expected errors[0].path to name only the failing JS field, got {errors[0].get('path')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
