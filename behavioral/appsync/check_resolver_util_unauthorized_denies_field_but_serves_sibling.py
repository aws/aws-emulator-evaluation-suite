"""resolver-util-unauthorized-denies-field-but-serves-sibling."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "resolver-util-unauthorized-denies-field-but-serves-sibling"
GROUP = "authorization"
SERVICES = ["appsync"]

SDL = """schema { query: Query }
type Query {
    secret: String
    open: String
}
"""
APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
JS_DENY = (
    "import { util } from '@aws-appsync/utils';\n"
    "export function request(ctx) {\n  util.unauthorized();\n}\n"
    "export function response(ctx) {\n  return 'leaked';\n}\n"
)
JS_OPEN = (
    "export function request(ctx) {\n  return { payload: 'open-ok' };\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A resolver calling util.unauthorized() denies only its field inside an HTTP 200: the field is
    nulled with one Unauthorized error, its response handler never runs, and a sibling resolves.
    """
    appsync = ctx.client("appsync")

    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-unauth-"),
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
    for field, code in (("secret", JS_DENY), ("open", JS_OPEN)):
        appsync.create_resolver(
            apiId=api_id, typeName="Query", fieldName=field, kind="UNIT",
            dataSourceName=ds_name, runtime=APPSYNC_JS, code=code,
        )
        ctx.on_cleanup(
            lambda f=field: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName=f)
        )
    key = appsync.create_api_key(apiId=api_id, description="sim2real-behav unauth key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=key))

    code, body = _poll_until(
        lambda: _post_json(ctx, url, {"x-api-key": key}, {"query": "query { open }"}),
        lambda res: res[0] == 200 and (res[1].get("data") or {}).get("open") == "open-ok",
        timeout_s=180.0, interval_s=5.0, description="the open resolver to answer",
    )
    assert "errors" not in body, f"the open field alone must carry no errors, got {body!r}"

    code, body = _post_json(ctx, url, {"x-api-key": key}, {"query": "query { secret open }"})
    assert code == 200, (
        f"a resolver-level util.unauthorized() is a per-field GraphQL error, not a request-level "
        f"rejection: expected HTTP 200, got {code!r} {body!r}"
    )
    data = body.get("data")
    assert isinstance(data, dict), f"the response must still carry a data object, got {body!r}"
    assert "secret" in data and data["secret"] is None, (
        f"the denied field must be present and nulled, got data={data!r}"
    )
    assert "leaked" not in json.dumps(body), (
        f"util.unauthorized() in request() must stop the field before response() runs, but the "
        f"response handler's value leaked: {body!r}"
    )
    assert data.get("open") == "open-ok", (
        f"the sibling field must still resolve in the same document, got data={data!r}"
    )
    errors = body.get("errors") or []
    assert len(errors) == 1, f"exactly one field was denied, so exactly one error: {errors!r}"
    err = errors[0]
    assert err.get("errorType") == "Unauthorized", (
        f"util.unauthorized() must surface errorType 'Unauthorized', got {err.get('errorType')!r}"
    )
    assert err.get("path") == ["secret"], f"the error must point at ['secret'], got {err.get('path')!r}"
    assert err.get("message") == "Not Authorized to access secret on type String", (
        f"unexpected denial message {err.get('message')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Bounded retry that raises on timeout instead of returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON and return (status, parsed_body); a 4xx/5xx is returned, not raised."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
