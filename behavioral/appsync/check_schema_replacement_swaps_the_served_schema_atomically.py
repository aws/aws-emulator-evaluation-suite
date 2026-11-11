"""schema-replacement-swaps-the-served-schema-atomically."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-replacement-swaps-the-served-schema-atomically"
GROUP = "schema"
SERVICES = ["appsync"]

SDL_V1 = """schema { query: Query }
type Query {
    keep(msg: String!): String
    alpha(msg: String!): String
}
"""

SDL_V2 = """schema { query: Query }
type Query {
    keep(msg: String!): String
    beta(msg: String!): String
}
"""

JS_ECHO = (
    "import { runtime } from '@aws-appsync/utils';\n"
    "export function request(ctx) {\n  runtime.earlyReturn(ctx.args.msg);\n  return {};\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
FIELD_UNDEFINED = "Validation error of type FieldUndefined"


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0, description="condition"):
    """Bounded retry that raises on timeout instead of returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _delete_resolver_if_present(svc, api_id, field):
    """Delete a resolver, treating not-found as done (``alpha``'s is deleted before the swap)."""
    try:
        svc.delete_resolver(apiId=api_id, typeName="Query", fieldName=field)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON and return (status, parsed_body); a 4xx/5xx is returned, not raised."""
    route_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        route_url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(ctx.http_verify)) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _await_schema(svc, api_id, sdl, *, description):
    """StartSchemaCreation + a bounded poll to a terminal status; returns the terminal response."""
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=300.0, interval_s=3.0,
        description=description,
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"{description}: expected SUCCESS/ACTIVE, got {status['status']!r} "
        f"details={status.get('details')!r}"
    )
    return status




@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A second StartSchemaCreation replaces the served schema: the removed field fails validation,
    the added field resolves, a shared field survives, and GetIntrospectionSchema agrees.
    """
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    url = (api.get("uris") or {}).get("GRAPHQL")
    assert url, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"

    _await_schema(svc, api_id, SDL_V1, description="the v1 schema to be created")

    ds_name = _alnum(ctx, "ds")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    for field in ("keep", "alpha"):
        svc.create_resolver(
            apiId=api_id, typeName="Query", fieldName=field, kind="UNIT",
            dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_ECHO,
        )
        ctx.on_cleanup(lambda _f=field: _delete_resolver_if_present(svc, api_id, _f))

    key = svc.create_api_key(apiId=api_id, description="sim2real-behav schema-swap key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))

    marker = ctx.unique_name("swap-")

    def _ask(field):
        return _post_json(
            ctx, url, {"x-api-key": key},
            {"query": f"query Q($m: String!) {{ {field}(msg: $m) }}",
             "variables": {"m": marker}},
        )

    _s, v1_body = _poll_until(
        lambda: _ask("alpha"),
        lambda res: res[0] == 200 and (res[1].get("data") or {}).get("alpha") == marker,
        timeout_s=180.0, interval_s=5.0,
        description="the v1 field 'alpha' to resolve on the live endpoint",
    )
    assert not v1_body.get("errors"), f"the v1 leg returned errors: {v1_body!r}"

    # Delete 'alpha''s resolver first so the swap never depends on whether AppSync tolerates a
    # resolver attached to a field the new schema removes.
    svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="alpha")
    terminal = _await_schema(svc, api_id, SDL_V2, description="the v2 schema to be created")
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="beta", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_ECHO,
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="beta"))
    frozen = [svc.get_schema_creation_status(apiId=api_id)["status"] for _ in range(3)]
    assert frozen == [terminal["status"]] * 3, (
        f"GetSchemaCreationStatus is a READ and must not advance the state machine: expected "
        f"three consecutive {terminal['status']!r}, got {frozen!r}"
    )

    # The added field resolving is the barrier proving v2 reached the endpoint.
    _s, v2_body = _poll_until(
        lambda: _ask("beta"),
        lambda res: res[0] == 200 and (res[1].get("data") or {}).get("beta") == marker,
        timeout_s=180.0, interval_s=5.0,
        description="the v2 field 'beta' to resolve, proving the swap reached the endpoint",
    )
    assert not v2_body.get("errors"), f"the v2 positive leg returned errors: {v2_body!r}"

    # Single-shot: 'beta' resolving above already proves v2 is the served schema, so a retry here
    # could only hide a target that keeps honouring the withdrawn field.
    gone_status, gone = _ask("alpha")
    assert gone_status == 200, (
        f"a parsed-but-invalid document rides a 200 GraphQL envelope, not an HTTP status: "
        f"expected 200 for the removed field, got {gone_status!r} body={gone!r}"
    )
    assert gone.get("data", "missing") is None, (
        f"a validation error resolves NOTHING, so data must be present and null: got "
        f"{gone.get('data', 'missing')!r} in {gone!r}"
    )
    gone_errors = gone.get("errors") or []
    assert gone_errors, f"the removed field must be refused, got no errors array: {gone!r}"
    joined = " | ".join(str(e.get("message", "")) for e in gone_errors)
    assert FIELD_UNDEFINED in joined, (
        f"expected a {FIELD_UNDEFINED!r} validation error for the field the v2 schema removed, "
        f"got {joined!r}"
    )
    assert "alpha" in joined, (
        f"the validation error must name the removed field 'alpha', got {joined!r}"
    )

    keep_status, keep_body = _ask("keep")
    assert keep_status == 200 and not keep_body.get("errors"), (
        f"the field present in BOTH schemas must still resolve after the swap: {keep_status!r} "
        f"{keep_body!r}"
    )
    assert (keep_body.get("data") or {}).get("keep") == marker, (
        f"expected the surviving field to echo {marker!r}, got {keep_body!r}"
    )

    sdl = svc.get_introspection_schema(
        apiId=api_id, format="SDL", includeDirectives=False
    )["schema"].read().decode("utf-8")
    assert "beta" in sdl, f"GetIntrospectionSchema does not name the added field: {sdl!r}"
    assert "alpha" not in sdl, (
        f"GetIntrospectionSchema still names the field the v2 schema removed, so the control "
        f"plane and the endpoint disagree: {sdl!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
