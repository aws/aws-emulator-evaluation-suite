"""api-key-expiry-ttl-enforced-denies-access."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "api-key-expiry-ttl-enforced-denies-access"
GROUP = "visibility-timeout-ttl"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateApiKey/UpdateApiKey reject an expires under 1 day without altering the key; a deleted
    key is refused at the GraphQL endpoint with 401 UnauthorizedException while a sibling key
    works.
    """
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    _deploy_minimal_schema(ctx, api_id)

    # The minimum key validity is 1 day, so a key cannot elapse within a run; deletion stands in
    # for expiry on the data plane below.
    now = int(time.time())
    too_soon = now + 3600  # 1 hour out -- well inside the "at least 1 day" floor.
    code, message = _error(
        lambda: appsync.create_api_key(apiId=api_id, description="too-soon", expires=too_soon)
    )
    assert code == "ApiKeyValidityOutOfBoundsException", (
        f"expected ApiKeyValidityOutOfBoundsException for a sub-1-day expires, got {code!r}"
    )
    assert message == "API key must be valid for a minimum of 1 days.", (
        f"expected AWS's exact minimum-validity message on CreateApiKey, got {message!r}"
    )

    valid_key = appsync.create_api_key(apiId=api_id, description="valid-key")["apiKey"]
    valid_key_id = valid_key["id"]
    valid_key_expires = valid_key["expires"]
    ctx.on_cleanup(lambda: _safe_delete_key(ctx, api_id, valid_key_id))

    # An UpdateApiKey that tries to pull `expires` inside the 1-day floor is rejected too, and
    # does not truncate the key's real expiry as a side effect.
    code2, message2 = _error(
        lambda: appsync.update_api_key(apiId=api_id, id=valid_key_id, expires=too_soon)
    )
    assert code2 == "ApiKeyValidityOutOfBoundsException", (
        f"expected ApiKeyValidityOutOfBoundsException on UpdateApiKey, got {code2!r}"
    )
    assert message2 == "API key must be valid for a minimum of 1 days.", (
        f"expected AWS's exact minimum-validity message on UpdateApiKey, got {message2!r}"
    )
    unchanged = next(
        k for k in appsync.list_api_keys(apiId=api_id)["apiKeys"] if k["id"] == valid_key_id
    )
    assert unchanged["expires"] == valid_key_expires, (
        "the rejected UpdateApiKey must not have altered the key's persisted expires"
    )

    endpoint = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]["uris"]["GRAPHQL"]
    query = "query { hello }"

    # A new API key or just-deployed resolver takes a few seconds to reach the data plane.
    status, payload = _wait_for_graphql_success(ctx, endpoint, valid_key_id, query, timeout_s=120.0, interval_s=5.0)
    assert status == 200 and "errors" not in payload, f"positive control failed: {status} {payload}"
    assert payload["data"]["hello"] == "hello-world"

    doomed_key = appsync.create_api_key(apiId=api_id, description="doomed-key")["apiKey"]["id"]
    appsync.delete_api_key(apiId=api_id, id=doomed_key)
    _wait_for_key_absent(ctx, api_id, doomed_key, timeout_s=60.0)

    status2, payload2 = _graphql_query(ctx, endpoint, doomed_key, query)
    assert status2 == 401, f"expected HTTP 401 for a deleted/invalid API key, got {status2} {payload2}"
    assert payload2.get("data") is None, f"expected no data payload for a denied key, got {payload2}"
    error_types = {e.get("errorType") for e in payload2.get("errors", [])}
    assert "UnauthorizedException" in error_types, (
        f"expected an UnauthorizedException error for the deleted key, got {payload2}"
    )

    # The sibling key still works, so the rejection was scoped to the deleted credential.
    status3, payload3 = _wait_for_graphql_success(ctx, endpoint, valid_key_id, query, timeout_s=60.0, interval_s=5.0)
    assert status3 == 200 and "errors" not in payload3
    assert payload3["data"]["hello"] == "hello-world"


def _error(fn):
    """Call fn() and return its botocore error (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-api-")
    api_id = appsync.create_graphql_api(name=name, authenticationType="API_KEY")["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _wait_for_schema_active(ctx, api_id, *, timeout_s=120.0, interval_s=3.0):
    appsync = ctx.client("appsync")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if last in ("SUCCESS", "ACTIVE"):
            return
        if last == "FAILED":
            raise AssertionError(f"schema creation FAILED for api {api_id}")
        time.sleep(interval_s)
    raise AssertionError(f"schema for {api_id} never became ACTIVE; last status {last!r}")


def _deploy_minimal_schema(ctx, api_id) -> None:
    """A trivial Query.hello field backed by a NONE data source, giving a live endpoint to call."""
    appsync = ctx.client("appsync")
    schema_def = "type Query {\n  hello: String\n}\n"
    appsync.start_schema_creation(apiId=api_id, definition=schema_def.encode("utf-8"))
    _wait_for_schema_active(ctx, api_id)

    appsync.create_data_source(apiId=api_id, name="NoneSource", type="NONE")
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="hello",
        dataSourceName="NoneSource",
        requestMappingTemplate='{\n  "version": "2017-02-28",\n  "payload": {}\n}',
        responseMappingTemplate='$util.toJson("hello-world")',
    )


def _wait_for_key_absent(ctx, api_id, key_id, *, timeout_s=60.0, interval_s=2.0):
    appsync = ctx.client("appsync")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ids = {k["id"] for k in appsync.list_api_keys(apiId=api_id)["apiKeys"]}
        if key_id not in ids:
            return
        time.sleep(interval_s)
    raise AssertionError(f"API key {key_id} was never removed from ListApiKeys within {timeout_s}s")


def _safe_delete_key(ctx, api_id, key_id) -> None:
    from botocore.exceptions import ClientError

    appsync = ctx.client("appsync")
    try:
        appsync.delete_api_key(apiId=api_id, id=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _http_post_json(ctx, url: str, headers: dict, body_obj: dict, timeout: float = 20.0):
    data = json.dumps(body_obj).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=data, headers={**headers, **route_headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _graphql_query(ctx, endpoint: str, api_key: str, query: str):
    headers = {"Content-Type": "application/json", "x-api-key": api_key}
    return _http_post_json(ctx, endpoint, headers, {"query": query})


def _wait_for_graphql_success(ctx, endpoint: str, api_key: str, query: str, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status, payload = None, None
    while time.monotonic() < deadline:
        status, payload = _graphql_query(ctx, endpoint, api_key, query)
        if status == 200 and "errors" not in payload:
            return status, payload
        time.sleep(interval_s)
    return status, payload


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
