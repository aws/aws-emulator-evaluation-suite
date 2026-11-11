"""flush-caches-bypass-ttl."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "flush-caches-bypass-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


_TTL_S = 300
_STABLE_RUN = 5


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """FlushStageCache invalidates the stage's response cache within a bound while the cached
    entry's 300 s TTL is live (the HTTP backend is reached again), and FlushStageAuthorizersCache
    is accepted on that stage without changing the response cache cluster's status."""
    apigw = ctx.client("apigateway")
    verify = ctx.http_verify

    # ---- backend: uncached, a fresh id per invocation ----
    backend_id = _create_api(ctx, apigw, "flush-caches-bypass-ttl-backend")
    backend_resource = _child(apigw, backend_id, "count")
    apigw.put_method(
        restApiId=backend_id, resourceId=backend_resource, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=backend_id,
        resourceId=backend_resource,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=backend_id, resourceId=backend_resource, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=backend_id,
        resourceId=backend_resource,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"reqId": "$context.requestId"}'},
    )
    backend_deployment = apigw.create_deployment(restApiId=backend_id)["id"]
    apigw.create_stage(restApiId=backend_id, stageName="b", deploymentId=backend_deployment)
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=backend_id, stageName="b"))
    backend_url = f"{ctx.rest_api_url(backend_id, 'b')}/count"
    # Control: the backend itself answers each invocation with a new id.
    first = _get_json_with_retries(backend_url, verify, timeout_s=120.0)
    second = _get_json_with_retries(backend_url, verify)
    assert first["reqId"] and first["reqId"] != second["reqId"], (
        f"the uncached backend must answer each invocation with a new id, got {first} then {second}"
    )

    # ---- front: HTTP_PROXY to the backend, per-method response caching ----
    api_id = _create_api(ctx, apigw, CHECK)
    resource_id = _child(apigw, api_id, "items")
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="HTTP_PROXY",
        integrationHttpMethod="GET",
        uri=backend_url,
    )

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "prod"
    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        cacheClusterEnabled=True,
        cacheClusterSize="0.5",
    )
    # Registered before the multi-minute provisioning wait: the cache cluster bills hourly.
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    status = _poll_until(
        lambda: apigw.get_stage(restApiId=api_id, stageName=stage_name)["cacheClusterStatus"],
        lambda s: s in ("AVAILABLE", "NOT_AVAILABLE"),
        timeout_s=_bounded(ctx, 600.0, reserve_s=150.0),
        interval_s=10,
    )
    assert status == "AVAILABLE", f"cache cluster failed to provision: {status}"

    # Per-method caching on GET /items, with a 300s TTL that does not expire during this check.
    # The resource path's "/" is escaped as "~1" in the patch path and in the methodSettings key.
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/~1items/GET/caching/enabled", "value": "true"},
            {"op": "replace", "path": "/~1items/GET/caching/ttlInSeconds", "value": str(_TTL_S)},
        ],
    )
    setting = apigw.get_stage(restApiId=api_id, stageName=stage_name).get("methodSettings", {})
    assert setting.get("~1items/GET", {}).get("cachingEnabled") is True and (
        setting["~1items/GET"].get("cacheTtlInSeconds") == _TTL_S
    ), f"GetStage must report caching on for ~1items/GET with a {_TTL_S}s TTL, got {setting}"

    url = f"{ctx.rest_api_url(api_id, stage_name)}/items"

    # Positive control: within the TTL, repeated requests are served from the cache. The
    # stage setting reaches the data plane eventually, so this polls (bounded) until a run of
    # consecutive responses carries one id: none of those requests reached the backend.
    cached_id, cached_since = _poll_for_stable_id(
        url, verify, timeout_s=_bounded(ctx, 180.0, reserve_s=150.0)
    )

    # FlushStageCache: accepted (202) immediately.
    flush_resp = apigw.flush_stage_cache(restApiId=api_id, stageName=stage_name)
    assert flush_resp["ResponseMetadata"]["HTTPStatusCode"] == 202, (
        f"expected FlushStageCache to be accepted immediately, got {flush_resp}"
    )

    # The flush takes effect asynchronously: within a bound, requests reach the backend again
    # and the cache settles on a fresh response, while the flushed entry's 300s TTL is still
    # live -- the flush, not expiry, invalidated it.
    _poll_for_stable_id(
        url, verify, timeout_s=_bounded(ctx, 180.0, reserve_s=60.0), exclude=cached_id
    )
    elapsed = time.monotonic() - cached_since
    assert elapsed < _TTL_S, (
        f"the cache must replace the flushed {cached_id!r} with a fresh response while its "
        f"{_TTL_S}s TTL is still live; that took {elapsed:.0f}s from the request that cached it"
    )

    cache_status_after_flush = _poll_until(
        lambda: apigw.get_stage(restApiId=api_id, stageName=stage_name)["cacheClusterStatus"],
        lambda s: s == "AVAILABLE",
        timeout_s=60,
        interval_s=2,
    )
    assert cache_status_after_flush == "AVAILABLE", (
        f"stage cache cluster did not settle back to AVAILABLE after FlushStageCache: "
        f"{cache_status_after_flush}"
    )

    # FlushStageAuthorizersCache: independent cache, must also succeed immediately.
    authz_flush_resp = apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)
    assert authz_flush_resp["ResponseMetadata"]["HTTPStatusCode"] == 202, (
        f"expected FlushStageAuthorizersCache to be accepted immediately, got {authz_flush_resp}"
    )

    # It can be invoked back-to-back without any cooldown/TTL wait imposed on the caller.
    authz_flush_resp_2 = apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)
    assert authz_flush_resp_2["ResponseMetadata"]["HTTPStatusCode"] == 202, (
        f"expected a second back-to-back FlushStageAuthorizersCache to also be accepted, "
        f"got {authz_flush_resp_2}"
    )

    # Terminal independent read: the authorizer cache is a separate cache from the
    # stage's response cache cluster, so the cluster proven AVAILABLE above must still
    # read back AVAILABLE, untouched by flushing the authorizer cache.
    after_authz_flush = apigw.get_stage(restApiId=api_id, stageName=stage_name)["cacheClusterStatus"]
    assert after_authz_flush == "AVAILABLE", (
        f"FlushStageAuthorizersCache must not disturb the independent response cache "
        f"cluster's status, got {after_authz_flush!r}"
    )


def _create_api(ctx, apigw, scenario: str) -> str:
    """A REGIONAL REST API carrying the sim2real marker, deleted in teardown."""
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-api-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real-check": scenario},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


def _child(apigw, api_id: str, path_part: str) -> str:
    root_id = next(i["id"] for i in apigw.get_resources(restApiId=api_id)["items"] if i["path"] == "/")
    return apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=path_part)["id"]


def _bounded(ctx, wanted_s: float, *, reserve_s: float) -> float:
    """`wanted_s`, cut so `reserve_s` of the check's budget is left for what follows."""
    left = ctx.time_left()
    return wanted_s if left is None else max(1.0, min(wanted_s, left - reserve_s))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _get_json_with_retries(url: str, verify, timeout_s: float = 60.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10, context=_ssl_context(verify)) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"never got a successful JSON response from {url}: {last_err}")


def _poll_for_stable_id(
    url: str, verify, *, timeout_s: float, exclude: str | None = None
) -> tuple[str, float]:
    """The id `_STABLE_RUN` consecutive GETs return (other than `exclude`), and the start of
    the earliest request that returned it: that request's backend invocation minted the id,
    so the cache entry holding it was written no earlier than then."""
    deadline = time.monotonic() + timeout_s
    first_seen: dict[str, float] = {}
    run_id, run_len = None, 0
    history: list[str] = []
    while time.monotonic() < deadline:
        started = time.monotonic()
        req_id = _get_json_with_retries(url, verify)["reqId"]
        first_seen.setdefault(req_id, started)
        history.append(req_id)
        run_len = run_len + 1 if req_id == run_id else 1
        run_id = req_id
        if run_len >= _STABLE_RUN and req_id != exclude:
            return req_id, first_seen[req_id]
        time.sleep(2)
    raise AssertionError(
        f"the cache never settled on one response{f' other than {exclude!r}' if exclude else ''} "
        f"for {_STABLE_RUN} consecutive GETs within {timeout_s:.0f}s; last ids {history[-8:]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
