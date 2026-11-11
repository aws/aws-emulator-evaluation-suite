"""graphql-field-level-auth-directive-denies-other-provider."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from behavioral_harness import tags

CHECK = "graphql-field-level-auth-directive-denies-other-provider"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query }
type Query {
    keyOnly: String @aws_api_key
    iamOnly: String @aws_iam
}
"""

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

    A transport failure returns status None so callers can keep polling a warming endpoint.
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


def _sigv4_headers(ctx, url, payload):
    """SigV4-sign ``payload`` for ``appsync`` with the check's own ``ctx.subprocess_env()`` keys.

    The ambient credential chain may be a different principal than the one the check runs as.
    """
    body = json.dumps(payload).encode()
    env = ctx.subprocess_env()
    akid = env.get("AWS_ACCESS_KEY_ID")
    assert akid, (
        "no signing credentials are reachable through ctx.subprocess_env(); the IAM-signed "
        "leg cannot be built"
    )
    creds = Credentials(akid, env["AWS_SECRET_ACCESS_KEY"], env.get("AWS_SESSION_TOKEN"))
    request = AWSRequest(
        method="POST", url=url, data=body,
        headers={"Content-Type": "application/json"},
    )
    SigV4Auth(creds, "appsync", ctx.region).add_auth(request)
    return dict(request.headers)


def _sigv4_gql(ctx, url, query, variables=None):
    payload = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    return _post_json(ctx, url, _sigv4_headers(ctx, url, payload), payload)


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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")

def run(ctx) -> None:
    """@aws_api_key / @aws_iam field directives deny per FIELD: 200 with a partial data+errors body.

    API-key and IAM callers each resolve their own field and get null plus an Unauthorized error
    for the other; an unknown api key is instead refused 401 at the transport level."""
    svc = ctx.client("appsync")
    api_id, url, api_key = _graphql_endpoint(
        ctx, svc, SDL,
        authenticationType="AWS_IAM",
        additionalAuthenticationProviders=[{"authenticationType": "API_KEY"}],
    )
    api = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert api["authenticationType"] == "AWS_IAM", api
    assert [p["authenticationType"] for p in api.get("additionalAuthenticationProviders") or []] == [
        "API_KEY"
    ], f"expected API_KEY registered as the additional provider, got {api!r}"

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))
    for field, value in (("keyOnly", "key-only-value"), ("iamOnly", "iam-only-value")):
        svc.create_resolver(
            apiId=api_id, typeName="Query", fieldName=field,
            kind="UNIT", dataSourceName=ds["name"],
            requestMappingTemplate=(
                '{"version":"2018-05-29","payload":' + json.dumps(value) + "}"
            ),
            responseMappingTemplate="$util.toJson($ctx.result)",
        )
        ctx.on_cleanup(
            lambda _f=field: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName=_f)
        )

    query = "query { keyOnly iamOnly }"
    status, body, _h = _poll_until(
        lambda: _gql(ctx, url, api_key, query),
        lambda res: res[0] is not None and isinstance(res[1].get("data"), dict) and bool(res[1].get("errors")),
        timeout_s=180, interval_s=5.0,
        description="the api-key request to produce a partial data+errors response",
    )
    assert status == 200, (
        f"a field-level authorization denial must be HTTP 200 with a partial body, not a 4xx; "
        f"got status={status} body={body!r}"
    )
    data = body["data"]
    assert data.get("keyOnly") == "key-only-value", (
        f"expected the @aws_api_key field to resolve for an API-key caller, got {data!r}"
    )
    assert data.get("iamOnly", "MISSING") is None, (
        f"expected the @aws_iam-only field to be present-and-null for an API-key caller, got {data!r}"
    )
    errors = body["errors"]
    assert len(errors) == 1, f"expected exactly one authorization error, got {errors!r}"
    assert errors[0].get("errorType") == "Unauthorized", (
        f"expected errorType 'Unauthorized' for the field-level denial, got {errors[0]!r}"
    )
    assert errors[0].get("path") == ["iamOnly"], (
        f"expected errors[0].path to name only the denied field, got {errors[0].get('path')!r}"
    )
    assert "iamOnly" in str(errors[0].get("message", "")), (
        f"expected the denial message to name the field, got {errors[0]!r}"
    )

    # Mirror leg: proves `iamOnly` is reachable, so the denial above is per auth provider.
    status, body, _h = _poll_until(
        lambda: _sigv4_gql(ctx, url, query),
        lambda res: res[0] is not None and isinstance(res[1].get("data"), dict) and bool(res[1].get("errors")),
        timeout_s=180, interval_s=5.0,
        description="the IAM-signed request to produce a partial data+errors response",
    )
    assert status == 200, (
        f"a field-level authorization denial must be HTTP 200 with a partial body, not a 4xx; "
        f"got status={status} body={body!r}"
    )
    data = body["data"]
    assert data.get("iamOnly") == "iam-only-value", (
        f"expected the @aws_iam field to resolve for an IAM caller, got {data!r}"
    )
    assert data.get("keyOnly", "MISSING") is None, (
        f"expected the @aws_api_key-only field to be present-and-null for an IAM caller, got {data!r}"
    )
    errors = body["errors"]
    assert len(errors) == 1, f"expected exactly one authorization error, got {errors!r}"
    assert errors[0].get("errorType") == "Unauthorized", (
        f"expected errorType 'Unauthorized' for the field-level denial, got {errors[0]!r}"
    )
    assert errors[0].get("path") == ["keyOnly"], (
        f"expected errors[0].path to name only the denied field, got {errors[0].get('path')!r}"
    )
    assert "keyOnly" in str(errors[0].get("message", "")), (
        f"expected the denial message to name the field, got {errors[0]!r}"
    )

    # Control: an unknown api key is a TRANSPORT-level refusal, not a field-level one --
    # the two must not collapse into each other.
    status, body, _h = _gql(ctx, url, "da2-sim2realbehavnotarealkey00", query)
    assert status == 401, (
        f"expected an unknown api key to be refused 401 at the transport level, "
        f"got status={status} body={body!r}"
    )
    assert body.get("data") is None, (
        f"expected no data for a transport-level auth failure, got {body.get('data')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
