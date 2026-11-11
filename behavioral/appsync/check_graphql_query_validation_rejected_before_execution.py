"""graphql-query-validation-rejected-before-execution."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-query-validation-rejected-before-execution"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query }
type Query {
    echo(id: ID!): String
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
    """A document that fails GraphQL validation is answered HTTP 200 with ``data: null`` and errors
    carrying no errorType, resolving nothing; a document AppSync cannot parse (or an empty query) is
    answered HTTP 400 MalformedHttpRequestException with no ``data`` key.
    """
    svc = ctx.client("appsync")
    api_id, url, api_key = _graphql_endpoint(
        ctx, svc, SDL, tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="echo",
        kind="UNIT", dataSourceName=ds["name"],
        requestMappingTemplate=(
            '{"version":"2018-05-29","payload":$util.toJson("echo-${ctx.args.id}")}'
        ),
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="echo"))

    valid = "query Q($id: ID!) { echo(id: $id) }"

    # Control FIRST: it also serves as the endpoint-warm gate.
    def _attempt_valid():
        return _gql(ctx, url, api_key, valid, {"id": "abc"})

    status, body, _h = _poll_until(
        _attempt_valid,
        lambda res: res[0] == 200 and isinstance(res[1].get("data"), dict),
        timeout_s=180, interval_s=5.0,
        description="the control query to execute on the live endpoint",
    )
    assert body["data"]["echo"] == "echo-abc", (
        f"control: expected the valid document to resolve, got {body!r}"
    )
    assert "errors" not in body, (
        f"control: a fully valid document must carry no errors array, got {body!r}"
    )

    # ---- class 1: parsed, then refused by VALIDATION -> 200 + envelope, nothing executed ----
    # Each entry: (label, query, variables, the symbol the message must name, the fragment that
    # identifies WHICH validation rule refused it).
    validation_cases = [
        ("undefined field", "query { nope }", None, "'nope'",
         "Validation error of type FieldUndefined"),
        ("unsupplied non-null variable", valid, {}, "'id'",
         "coerced Null value for NonNull type 'ID!'"),
        ("variable whose value cannot coerce", valid, {"id": {"not": "an ID"}}, "'id'",
         "has an invalid value"),
    ]
    for label, query, variables, symbol, rule in validation_cases:
        status, body, _h = _gql(ctx, url, api_key, query, variables)
        assert status == 200, (
            f"{label}: a GraphQL VALIDATION error is reported inside the response envelope, so "
            f"the HTTP status must stay 200; got status={status} body={body!r}"
        )
        errors = body.get("errors")
        assert isinstance(errors, list) and errors, (
            f"{label}: expected a non-empty errors array, got {body!r}"
        )
        # The data entry is PRESENT and null: the document was rejected before execution, so
        # nothing resolved -- but AppSync still emits the key, unlike the parse-failure envelope
        # below. An implementation that partially resolves the document fails here.
        assert "data" in body, (
            f"{label}: a validation failure still returns a GraphQL envelope with a data entry, "
            f"got keys {sorted(body)}"
        )
        assert body["data"] is None, (
            f"{label}: validation happens BEFORE execution, so data must be null, got "
            f"{body['data']!r}"
        )
        message = " ".join(str(e.get("message", "")) for e in errors)
        assert symbol in message, (
            f"{label}: expected the error message to name {symbol}, got {message!r}"
        )
        assert rule in message, (
            f"{label}: expected the message to identify the rule that refused it ({rule!r}), "
            f"got {message!r}"
        )
        first = errors[0]
        # Shape of a REQUEST error, as distinct from a field error: located in the document,
        # attached to no response path, and not one of AppSync's typed data-plane errors.
        assert first.get("path") is None, (
            f"{label}: a request error is not attached to a response path, got "
            f"path={first.get('path')!r}"
        )
        assert "errorType" not in first, (
            f"{label}: a GraphQL validation error must not be typed as an AppSync data-plane "
            f"error, got errorType={first.get('errorType')!r}"
        )
        locations = first.get("locations")
        assert isinstance(locations, list) and locations, (
            f"{label}: a validation error must point at a location in the document, got "
            f"{first!r}"
        )
        assert isinstance(locations[0].get("line"), int) and isinstance(
            locations[0].get("column"), int
        ), f"{label}: locations must carry integer line/column, got {locations!r}"

    # ---- class 2: never parsed -> the HTTP front door refuses it, no GraphQL envelope ----
    parse_cases = [
        ("syntax error", "query { echo(id: }", "Unable to parse GraphQL query."),
        ("empty query", "", "Invalid request, `query` can't be empty."),
    ]
    parse_messages = []
    for label, query, expected_message in parse_cases:
        status, body, _h = _gql(ctx, url, api_key, query)
        assert status == 400, (
            f"{label}: a body AppSync cannot turn into a GraphQL operation is refused by the "
            f"HTTP layer with 400, got status={status} body={body!r}"
        )
        assert "data" not in body, (
            f"{label}: a request that never became a GraphQL operation must carry no data "
            f"entry at all, got keys {sorted(body)}"
        )
        errors = body.get("errors")
        assert isinstance(errors, list) and len(errors) == 1, (
            f"{label}: expected exactly one front-door error, got {body!r}"
        )
        assert errors[0].get("errorType") == "MalformedHttpRequestException", (
            f"{label}: expected errorType MalformedHttpRequestException, got "
            f"{errors[0].get('errorType')!r}"
        )
        assert errors[0].get("message") == expected_message, (
            f"{label}: expected message {expected_message!r}, got "
            f"{errors[0].get('message')!r}"
        )
        assert "locations" not in errors[0], (
            f"{label}: a body that was never parsed cannot carry document locations, got "
            f"{errors[0]!r}"
        )
        parse_messages.append(errors[0]["message"])

    assert parse_messages[0] != parse_messages[1], (
        f"an unparseable document and an empty query are different front-door failures but "
        f"produced the identical message {parse_messages[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
