"""graphql-introspection-query-and-disabled-config."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-introspection-query-and-disabled-config"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query }
type Query {
    ping: String
    widget: Widget
}
type Widget {
    id: ID!
    name: String
}
"""

INTROSPECTION_QUERY = (
    "query {"
    " __schema { queryType { name } }"
    ' __type(name: "Widget") { name kind fields { name type { kind name ofType { kind name } } } }'
    " }"
)

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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")

def run(ctx) -> None:
    """Introspection returns the compiled schema (NON_NULL wrappers included); with
    introspectionConfig=DISABLED the same document is a 200 envelope of FieldUndefined errors and
    nothing resolved, while ordinary fields and ``__typename`` keep working.
    """
    svc = ctx.client("appsync")
    api_id, url, api_key = _graphql_endpoint(ctx, svc, SDL)
    api_name = svc.get_graphql_api(apiId=api_id)["graphqlApi"]["name"]

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="ping",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate='{"version":"2018-05-29","payload":"pong"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping"))

    # 1. Introspection is ENABLED by default and describes the compiled schema.
    status, body, _h = _poll_until(
        lambda: _gql(ctx, url, api_key, INTROSPECTION_QUERY),
        lambda res: res[0] == 200 and isinstance(res[1].get("data"), dict) and not res[1].get("errors"),
        timeout_s=180, interval_s=5.0,
        description="the introspection query to succeed on the live endpoint",
    )
    data = body["data"]
    assert data["__schema"]["queryType"]["name"] == "Query", (
        f"expected __schema.queryType.name to be the SDL's query root, got {data['__schema']!r}"
    )
    widget = data["__type"]
    assert widget["name"] == "Widget" and widget["kind"] == "OBJECT", (
        f"expected __type(name: 'Widget') to describe an OBJECT type, got {widget!r}"
    )
    fields = {f["name"]: f["type"] for f in widget["fields"]}
    assert set(fields) == {"id", "name"}, (
        f"expected exactly the two declared fields on Widget, got {sorted(fields)}"
    )
    assert fields["id"]["kind"] == "NON_NULL" and fields["id"]["ofType"]["name"] == "ID", (
        f"expected 'id: ID!' to introspect as NON_NULL wrapping ID, got {fields['id']!r}"
    )
    assert fields["name"]["kind"] == "SCALAR" and fields["name"]["name"] == "String", (
        f"expected 'name: String' to introspect as the SCALAR String, got {fields['name']!r}"
    )

    # 2. Disable introspection. UpdateGraphqlApi is a full replace, so re-supply the identity.
    svc.update_graphql_api(
        apiId=api_id, name=api_name, authenticationType="API_KEY", introspectionConfig="DISABLED"
    )
    assert svc.get_graphql_api(apiId=api_id)["graphqlApi"]["introspectionConfig"] == "DISABLED", (
        "expected the control plane to persist introspectionConfig=DISABLED"
    )

    # AppSync does not implement DISABLED as a request-level refusal.
    # It STRIPS the introspection fields out of the compiled schema, so
    # the very same document now fails ordinary GraphQL VALIDATION: HTTP 200, data present and
    # null, and one FieldUndefined error per introspection subfield the document selected --
    # e.g. "Validation error of type FieldUndefined: Field 'queryType' in type '__Schema' is
    # undefined @ '__schema/queryType'". The word "introspection" never appears anywhere in the
    # response, and the status is never 400. What the response DOES prove is that the meta
    # types lost their fields, which is why every error names __Schema or __Type.
    status, body, _h = _poll_until(
        lambda: _gql(ctx, url, api_key, INTROSPECTION_QUERY),
        lambda res: res[0] is not None and bool(res[1].get("errors")),
        timeout_s=180, interval_s=5.0,
        description="introspectionConfig=DISABLED to propagate to the data plane",
    )
    assert status == 200, (
        f"disabling introspection removes the introspection fields from the schema, so the "
        f"query fails validation inside a 200 GraphQL envelope; got status={status} body={body!r}"
    )
    assert "data" in body and body["data"] is None, (
        f"a document refused by validation must carry a present-but-null data entry and must "
        f"resolve nothing, got keys {sorted(body)} data={body.get('data')!r}"
    )
    errors = body["errors"]
    # One error per introspection subfield the document asked for: queryType on __Schema, and
    # name/kind/fields on __Type. Every one of them must be a FieldUndefined validation error.
    for err in errors:
        message = str(err.get("message", ""))
        assert "Validation error of type FieldUndefined" in message, (
            f"with introspection disabled each error must be a FieldUndefined validation error "
            f"(the field is gone from the schema), got {err!r}"
        )
        assert err.get("path") is None and "errorType" not in err, (
            f"a validation error is not attached to a response path and is not a typed AppSync "
            f"data-plane error, got {err!r}"
        )
    messages = " ".join(str(e.get("message", "")) for e in errors)
    assert "'__Schema'" in messages, (
        f"expected the refusal to report the selected field as undefined on the __Schema meta "
        f"type, got {messages!r}"
    )
    assert "'__Type'" in messages, (
        f"expected the refusal to report the selected fields as undefined on the __Type meta "
        f"type, got {messages!r}"
    )
    assert "queryType" in messages, (
        f"expected __schema/queryType to be named as the undefined selection, got {messages!r}"
    )

    # 3. Controls: the flag removes introspection ONLY.
    # 3a. An ordinary field still executes.
    status, body, _h = _gql(ctx, url, api_key, "query { ping }")
    assert status == 200 and body.get("data", {}).get("ping") == "pong", (
        f"expected normal field execution to keep working with introspection disabled, "
        f"got status={status} body={body!r}"
    )
    assert "errors" not in body, (
        f"an ordinary field query must be error-free with introspection disabled, got {body!r}"
    )
    # 3b. __typename -- a meta field the GraphQL spec requires on every type, and which is NOT
    # part of introspection -- still resolves. An implementation that blanket-rejects every
    # field starting with "__" breaks clients here while looking correct above.
    status, body, _h = _gql(ctx, url, api_key, "query { __typename ping }")
    assert status == 200, f"__typename must stay available, got status={status} body={body!r}"
    assert body.get("data", {}).get("__typename") == "Query", (
        f"__typename is not introspection and must still resolve to the query root type name, "
        f"got {body!r}"
    )
    assert "errors" not in body, (
        f"__typename must not be refused with introspection disabled, got {body!r}"
    )

    # 4. Restore: re-enabling introspectionConfig brings back the SAME introspection this
    # check just proved was refused -- so step 2 measured the flag's effect, not a resolver
    # that broke and stayed broken.
    svc.update_graphql_api(
        apiId=api_id, name=api_name, authenticationType="API_KEY", introspectionConfig="ENABLED"
    )
    assert svc.get_graphql_api(apiId=api_id)["graphqlApi"]["introspectionConfig"] == "ENABLED", (
        "expected the control plane to persist introspectionConfig=ENABLED after restoring it"
    )
    status, body, _h = _poll_until(
        lambda: _gql(ctx, url, api_key, INTROSPECTION_QUERY),
        lambda res: res[0] == 200 and isinstance(res[1].get("data"), dict) and not res[1].get("errors"),
        timeout_s=180, interval_s=5.0,
        description="introspectionConfig=ENABLED to restore the data plane to the identical query",
    )
    data = body["data"]
    assert data["__schema"]["queryType"]["name"] == "Query", (
        f"expected the SAME introspection query to resolve __schema again once re-enabled, "
        f"got {data['__schema']!r}"
    )
    widget = data["__type"]
    assert widget["name"] == "Widget" and widget["kind"] == "OBJECT", (
        f"expected the SAME introspection query to resolve Widget again once re-enabled, "
        f"got {widget!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
