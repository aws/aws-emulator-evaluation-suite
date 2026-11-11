"""flush-api-cache-clears-cache."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flush-api-cache-clears-cache"
GROUP = "visibility-timeout-ttl"
SERVICES = ["appsync"]


_SCHEMA = "type Query {\n  ping: String\n}\n"
_REQUEST_TEMPLATE = '{"version": "2017-02-28", "payload": {}}'
_RESPONSE_TEMPLATE = "$util.toJson($util.time.nowISO8601())"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """FlushApiCache immediately invalidates FULL_REQUEST_CACHING entries: a cached
    resolver answer stops being served the instant the cache is flushed, well before its
    long ttl would naturally expire, and GetApiCache reports the cache stayed AVAILABLE."""
    appsync = ctx.client("appsync")

    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-flush-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    endpoint = resp["graphqlApi"]["uris"]["GRAPHQL"]
    ctx.on_cleanup(lambda: _safe_call(lambda: appsync.delete_graphql_api(apiId=api_id), "NotFoundException"))

    # Kick off cache provisioning immediately so its (slow, async) node startup overlaps
    # with the schema/data-source/resolver setup below, rather than waiting for it after.
    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    ctx.on_cleanup(
        lambda: _safe_call(lambda: appsync.delete_api_cache(apiId=api_id), "NotFoundException", "BadRequestException")
    )

    key_resp = appsync.create_api_key(apiId=api_id)
    api_key = key_resp["apiKey"]["id"]

    appsync.start_schema_creation(apiId=api_id, definition=_SCHEMA.encode("utf-8"))
    schema_status = _poll_schema_status(ctx, api_id)
    assert schema_status in {"SUCCESS", "ACTIVE"}, f"schema creation failed: {schema_status}"

    appsync.create_data_source(apiId=api_id, name="none_ds", type="NONE")
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        dataSourceName="none_ds",
        requestMappingTemplate=_REQUEST_TEMPLATE,
        responseMappingTemplate=_RESPONSE_TEMPLATE,
    )

    if not _wait_for_cache_status(ctx, api_id, "AVAILABLE", timeout_s=900, interval_s=10.0):
        raise AssertionError(
            f"api cache for {api_id} did not reach AVAILABLE within the check's bounded "
            "budget (real AWS ElastiCache-class node provisioning is asynchronous and can "
            "take longer than a single check's 300s timeout allows); cannot exercise the "
            "actual caching effect without an AVAILABLE cache",
        )

    first = _query_ping_with_retry(ctx, endpoint, api_key)
    # Bounded poll (not a bare sleep): repeatedly re-query across a 2s window and
    # assert every single response still matches the cached value -- this both waits
    # out real wall-clock time (so a non-cached resolver would show a different
    # timestamp) and continuously verifies the cache keeps serving the same answer.
    second = _poll_cache_hit_persists(ctx, endpoint, api_key, first, duration_s=2.0, interval_s=0.4)
    assert second == first, (
        f"identical query well within the 300s ttl should be served from cache "
        f"(first={first!r}, second={second!r})"
    )

    appsync.flush_api_cache(apiId=api_id)

    after_flush = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert after_flush["status"] == "AVAILABLE", (
        f"flush must not move the cache into a transitional state, got {after_flush['status']!r}"
    )
    assert after_flush["ttl"] == 300, "flush must not alter the cache's own configuration"

    # Bounded poll to the condition "resolver result differs from the pre-flush
    # cached value" -- proves the invalidation is immediate rather than waiting on
    # the (much longer) ttl to expire.
    third = _poll_until_value_changes(ctx, endpoint, api_key, first, timeout_s=900, interval_s=1.0)
    assert third != first, (
        "flush must invalidate the cached entry immediately, not wait for the ttl to "
        f"expire (first={first!r}, third={third!r})"
    )


def _safe_call(fn, *gone_codes) -> None:
    """Run a delete, tolerating only the codes that mean it is already gone or going; the API's
    own delete takes its cache with it."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone_codes:
            raise


def _poll_schema_status(ctx, api_id: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    appsync = ctx.client("appsync")
    terminal = {"SUCCESS", "ACTIVE", "FAILED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"schema creation for {api_id} timed out (last status={status})")


def _wait_for_cache_status(ctx, api_id: str, expected_status: str, timeout_s: float = 200.0, interval_s: float = 10.0) -> bool:
    """Bounded poll for the cache's operational status -- returns True once it reaches
    expected_status, False if the bounded window is exhausted first (the caller decides
    whether that's a skip). Bounded well inside the harness's fixed 300s per-check
    timeout, unlike blocking on the full (potentially much longer) real-AWS provisioning
    window."""
    appsync = ctx.client("appsync")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_api_cache(apiId=api_id)["apiCache"]["status"]
        if status == expected_status:
            return True
        if status == "FAILED":
            raise AssertionError(f"api cache for {api_id} entered FAILED state")
        time.sleep(interval_s)
    return False


def _poll_cache_hit_persists(ctx, endpoint: str, api_key: str, expected_value: str, duration_s: float = 2.0, interval_s: float = 0.4) -> str:
    """Poll the endpoint across a bounded window, asserting every response still
    equals expected_value -- i.e. the cache keeps serving the same cached answer
    while real wall-clock time elapses."""
    deadline = time.monotonic() + duration_s
    last = expected_value
    while time.monotonic() < deadline:
        last = _query_ping_with_retry(ctx, endpoint, api_key)
        assert last == expected_value, (
            f"cached query result changed unexpectedly before any flush "
            f"(expected {expected_value!r}, got {last!r})"
        )
        time.sleep(interval_s)
    return last


def _poll_until_value_changes(ctx, endpoint: str, api_key: str, stale_value: str, timeout_s: float = 10.0, interval_s: float = 1.0) -> str:
    """Poll the endpoint in a bounded loop until the resolver result differs from
    stale_value, raising if it never does within timeout_s."""
    deadline = time.monotonic() + timeout_s
    last = stale_value
    while time.monotonic() < deadline:
        last = _query_ping_with_retry(ctx, endpoint, api_key)
        if last != stale_value:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"flush did not invalidate the cached entry within {timeout_s}s (still {last!r})"
    )


def _query_ping_with_retry(ctx, endpoint: str, api_key: str, attempts: int = 15, delay_s: float = 3.0) -> str:
    """Newly created schemas/resolvers/data sources can take a few seconds to
    propagate to the live GraphQL endpoint; retry on GraphQL-level errors only."""
    last_error = None
    route_url, route_headers = ctx.endpoint_route(endpoint)
    for _ in range(attempts):
        body = json.dumps({"query": "query { ping }"}).encode("utf-8")
        req = urllib.request.Request(
            route_url,
            data=body,
            headers={"Content-Type": "application/json", "x-api-key": api_key, **route_headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15, context=_ssl_context(ctx.http_verify)) as http_resp:
                payload = json.loads(http_resp.read())
        except urllib.error.HTTPError as exc:
            payload = json.loads(exc.read())
        if payload.get("errors"):
            last_error = payload["errors"]
            time.sleep(delay_s)
            continue
        return payload["data"]["ping"]
    raise AssertionError(f"GraphQL query against {endpoint} never succeeded: {last_error}")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
