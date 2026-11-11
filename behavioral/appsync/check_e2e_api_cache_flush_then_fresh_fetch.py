"""e2e-api-cache-flush-then-fresh-fetch."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-api-cache-flush-then-fresh-fetch"
GROUP = "end-to-end"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With FULL_REQUEST_CACHING, two identical queries return the same cached value; after
    FlushApiCache the next one is freshly computed, and the cache config is unchanged."""
    appsync = ctx.client("appsync")
    teardown = _Teardown()

    api_name = _safe_graphql_name(ctx, "sim2real_cacheapi")
    api = appsync.create_graphql_api(
        name=api_name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: _settle(lambda: appsync.delete_graphql_api(apiId=api_id), teardown))

    schema = "schema {\n  query: Query\n}\ntype Query {\n  now: String\n}\n"
    appsync.start_schema_creation(apiId=api_id, definition=schema.encode("utf-8"))
    _wait_for_schema_creation(appsync, api_id)

    appsync.create_data_source(apiId=api_id, name="NoneDS", type="NONE")
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="now",
        dataSourceName="NoneDS",
        requestMappingTemplate='{\n  "version": "2017-02-28",\n  "payload": {}\n}',
        # Millisecond precision, not nowISO8601()'s whole-second precision: two back-to-back
        # HTTP round trips are commonly under a second apart, so a whole-second value would
        # often coincide by luck alone and let a target that never caches anything pass the
        # "second call replays the first" assertion below.
        responseMappingTemplate=(
            '$util.toJson($util.time.nowFormatted("yyyy-MM-dd\'T\'HH:mm:ss.SSS\'Z\'"))'
        ),
    )
    api_key = appsync.create_api_key(apiId=api_id)["apiKey"]["id"]

    appsync.create_api_cache(apiId=api_id, ttl=60, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL")
    ctx.on_cleanup(lambda: _settle(lambda: appsync.delete_api_cache(apiId=api_id), teardown))
    cache = _wait_for_cache_status(appsync, api_id, "AVAILABLE")
    assert cache["ttl"] == 60
    assert cache["apiCachingBehavior"] == "FULL_REQUEST_CACHING"

    graphql_url = _find_https_graphql_uri(api["uris"])

    def _fetch_now() -> str:
        status, body = _graphql_request(ctx, graphql_url, api_key, "query { now }")
        assert status == 200, body
        assert not body.get("errors"), body.get("errors")
        return body["data"]["now"]

    # Freeze detector, no retry-on-mismatch: a cache that is truly AVAILABLE must replay the
    # exact cached response on the very next identical query. Retrying until two calls happen
    # to agree would tolerate a target that never caches anything at all.
    v1 = _fetch_now()
    v2 = _fetch_now()
    assert v1 == v2, f"expected second identical query to hit the cache, got {v1!r} then {v2!r}"

    appsync.flush_api_cache(apiId=api_id)

    # Bounded retry, not a fixed sleep: FlushApiCache's effect on the next read is not
    # guaranteed synchronous, so poll for the resolver-fresh value with a stated deadline
    # instead of assuming a fixed delay is always enough (or waiting longer than needed).
    _poll_until_changed(_fetch_now, v1, timeout_s=30.0, interval=2.0)

    cache_after = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert cache_after["ttl"] == 60
    assert cache_after["apiCachingBehavior"] == "FULL_REQUEST_CACHING"
    assert cache_after["status"] == "AVAILABLE"


#: Seconds every teardown of one run shares: the suite's 900 s cleanup budget less a 120 s margin.
_CLEANUP_S = 780.0


class _Teardown:
    """One deadline for all of a run's teardowns, started when the first of them runs."""

    def __init__(self) -> None:
        self._at = None

    def deadline(self) -> float:
        if self._at is None:
            self._at = time.monotonic() + _CLEANUP_S
        return self._at


def _settle(fn, teardown) -> None:
    """Run a teardown call: NotFoundException means gone; ConcurrentModificationException (the
    API cache still deleting) is retried every 2 s to the shared deadline; anything else raises."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "ConcurrentModificationException" or time.monotonic() >= teardown.deadline():
                raise
        time.sleep(2)


def _safe_graphql_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c if (c.isalnum() or c == "_") else "_" for c in raw)
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = "a" + cleaned
    return cleaned[:64]


def _wait_for_schema_creation(appsync, api_id: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError(f"schema creation failed for api {api_id}")
        time.sleep(2)
    raise AssertionError(f"schema creation for {api_id} never reached SUCCESS, last status={status!r}")


def _wait_for_cache_status(appsync, api_id: str, want_status: str, timeout_s: float = 900.0) -> dict:
    deadline = time.monotonic() + timeout_s
    cache = None
    while time.monotonic() < deadline:
        cache = appsync.get_api_cache(apiId=api_id)["apiCache"]
        if cache["status"] == want_status:
            return cache
        if cache["status"] == "FAILED":
            raise AssertionError(f"api cache for {api_id} entered FAILED status")
        time.sleep(2)
    raise AssertionError(f"api cache for {api_id} never reached {want_status}, last={cache!r}")


def _find_https_graphql_uri(uris: dict) -> str:
    # AppSync's REALTIME (wss://) uri also ends in "/graphql", so a bare suffix match on all
    # values is ambiguous between it and the https GRAPHQL endpoint -- match on scheme too.
    for value in uris.values():
        if value.startswith("https://") and value.endswith("/graphql"):
            return value
    raise AssertionError(f"no https graphql uri in {uris!r}")


def _graphql_request(ctx, url: str, api_key: str, query: str, variables: dict | None = None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "x-api-key": api_key, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _poll_until_changed(query_fn, prior_value: str, timeout_s: float, interval: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = prior_value
    while time.monotonic() < deadline:
        last = query_fn()
        if last != prior_value:
            return last
        time.sleep(interval)
    raise AssertionError(
        f"post-flush query kept returning the stale cached value {prior_value!r} after {timeout_s}s"
        f" (last={last!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
