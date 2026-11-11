"""flush-stage-cache-bypasses-ttl."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "flush-stage-cache-bypasses-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


# A MOCK integration response templated with $context.requestId cannot prove this: real AWS
# re-evaluates that context variable on every call regardless of caching, because a MOCK integration
# has no backend invocation for the cache to actually skip -- the "same requestId on a cache hit"
# premise never holds for it. The backend below is a real Lambda that returns a freshly generated
# UUID on every invocation, so two calls observing the same value can only mean the second one never
# reached the backend at all -- i.e. it was served from cache.
_BACKEND_CODE = """
import json
import uuid

def handler(event, context):
    return {"statusCode": 200, "body": json.dumps({"reqId": str(uuid.uuid4())})}
"""


#: A fresh stage cache cluster's provisioning plus warm-up, on AWS: minutes, not seconds.
CACHE_HIT_TIMEOUT_S = 900.0
#: The method's response-cache TTL, in seconds.
TTL_S = 300.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """FlushStageCache forces the next request on a stage to bypass a method's
    response-cache TTL and re-run the integration immediately, even though the TTL
    (300s) is nowhere near expiring."""
    apigw = ctx.client("apigateway")

    lambda_arn = _create_backend_lambda(ctx)

    rest_api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-flushcache-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]

    resource_id = apigw.create_resource(restApiId=rest_api_id, parentId=root_id, pathPart="cachetest")["id"]
    apigw.put_method(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{rest_api_id}/*/GET/cachetest"
    _allow_apigateway_invoke(ctx, lambda_arn, source_arn)

    deployment_id = apigw.create_deployment(restApiId=rest_api_id)["id"]
    stage_name = "test"
    apigw.create_stage(
        restApiId=rest_api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        cacheClusterEnabled=True,
        cacheClusterSize="0.5",
    )
    # Registered before the multi-minute provisioning wait below: an orphaned cache cluster
    # bills hourly, and the wait is exactly where this check can die.
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=rest_api_id, stageName=stage_name))

    apigw.update_stage(
        restApiId=rest_api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/~1cachetest/GET/caching/enabled", "value": "true"},
            {"op": "replace", "path": "/~1cachetest/GET/caching/ttlInSeconds", "value": "300"},
        ],
    )

    url = f"{ctx.rest_api_url(rest_api_id, stage_name)}/cachetest"

    # A fresh 0.5GB cluster takes minutes to provision and longer still to serve its first hit,
    # and per-method caching reaches GetStage later than that. The endpoint is the only
    # observable that matters, so provisioning and warm-up fold into one poll of it.
    call_a, call_b, cached_at = _wait_for_cache_hit(ctx, url, timeout_s=CACHE_HIT_TIMEOUT_S)
    assert call_a["reqId"] == call_b["reqId"], (
        f"expected two calls within the 300s TTL to be served from cache, "
        f"got {call_a} then {call_b}"
    )

    # Cheap and one-shot, not polled: two calls were just observed being served from cache, which
    # is only possible with an AVAILABLE cluster, so this is confirming the target's own reported
    # state agrees with the behavior already proven above rather than re-deriving it.
    stage_after_hit = apigw.get_stage(restApiId=rest_api_id, stageName=stage_name)
    assert stage_after_hit.get("cacheClusterStatus") == "AVAILABLE", (
        f"expected an AVAILABLE cache cluster given the cache hit just observed, got "
        f"{stage_after_hit.get('cacheClusterStatus')!r}"
    )

    flush_resp = apigw.flush_stage_cache(restApiId=rest_api_id, stageName=stage_name)
    assert flush_resp["ResponseMetadata"]["HTTPStatusCode"] == 202, flush_resp

    # cacheClusterStatus should settle back to AVAILABLE promptly after the flush -- this
    # transition is fast (seconds), unlike the initial multi-minute provisioning above.
    assert _wait_for_cache_status(
        ctx, rest_api_id, stage_name, "AVAILABLE", timeout_s=60.0
    ), "cacheClusterStatus never returned to AVAILABLE after FlushStageCache"

    # The flush reaches every cache node within seconds, not at once: poll for the first fresh
    # invocation, well inside the 300s TTL the cached entry still had.
    # The wait ends when the cached entry's own TTL would have expired it, counted from the
    # request that cached it: a fresh invocation only after that proves nothing about the flush.
    call_c = _wait_for_fresh(ctx, url, call_b["reqId"], until=cached_at + TTL_S)
    fresh_after_s = time.monotonic() - cached_at
    assert fresh_after_s < TTL_S, (
        f"no fresh invocation until {fresh_after_s:.0f}s after the entry was cached, past its "
        f"{TTL_S:.0f}s TTL, so FlushStageCache never evicted it"
    )
    assert call_c["reqId"] != call_b["reqId"], (
        f"expected FlushStageCache to force a fresh integration invocation despite the "
        f"300s TTL, got {call_b} then {call_c}"
    )


def _budget_s(ctx, timeout_s: float) -> float:
    """A wait's timeout bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))


def _not_graded(start: float, timeout_s: float, what: str) -> TimeoutError:
    return TimeoutError(
        f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
        f"{timeout_s:.0f}s wait for {what} ended; not graded"
    )


def _wait_for_cache_status(ctx, rest_api_id: str, stage_name: str, want: str, timeout_s: float) -> bool:
    apigw = ctx.client("apigateway")
    start = time.monotonic()
    cap_s = _budget_s(ctx, timeout_s)
    while True:
        status = apigw.get_stage(restApiId=rest_api_id, stageName=stage_name).get("cacheClusterStatus")
        if status == want:
            return True
        if time.monotonic() - start >= cap_s:
            if cap_s < timeout_s:
                raise _not_graded(start, timeout_s, f"cacheClusterStatus {want}")
            return False
        time.sleep(2.0)


def _get_json_with_retries(ctx, url: str, timeout_s: float = 60.0) -> dict[str, Any]:
    start = time.monotonic()
    cap_s = _budget_s(ctx, timeout_s)
    while True:
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
        if time.monotonic() - start >= cap_s:
            if cap_s < timeout_s:
                raise _not_graded(start, timeout_s, f"a successful response from {url}")
            raise AssertionError(f"never got a successful response from {url}: {last_err}")
        time.sleep(2.0)


def _wait_for_fresh(ctx, url: str, cached_id: str, until: float) -> dict[str, Any]:
    """Poll the endpoint every 2 s until it answers with a reqId other than ``cached_id``, or
    until the monotonic instant ``until``."""
    start = time.monotonic()
    timeout_s = max(0.0, until - start)
    cap_s = _budget_s(ctx, timeout_s)
    while True:
        call = _get_json_with_retries(ctx, url, timeout_s=15.0)
        if call["reqId"] != cached_id or time.monotonic() >= until:
            return call
        if time.monotonic() - start >= cap_s:
            raise _not_graded(start, timeout_s, "a fresh invocation after FlushStageCache")
        time.sleep(2.0)


def _wait_for_cache_hit(ctx, url: str, timeout_s: float) -> tuple[dict, dict, float]:
    """Poll the endpoint until two consecutive calls return the same reqId.

    The first call(s) right after enabling per-method caching may still bypass the cache
    while it warms up even though the setting is already active, so this asserts on the
    first *repeat* observed rather than on the very next call. Also returns when the request
    that cached the entry was sent, the earliest its TTL can count from.
    """
    start = time.monotonic()
    cap_s = _budget_s(ctx, timeout_s)
    asked_at = time.monotonic()
    baseline = _get_json_with_retries(ctx, url, timeout_s=15.0)
    while True:
        candidate_at = time.monotonic()
        candidate = _get_json_with_retries(ctx, url, timeout_s=15.0)
        if candidate["reqId"] == baseline["reqId"]:
            return baseline, candidate, asked_at
        baseline, asked_at = candidate, candidate_at
        if time.monotonic() - start >= cap_s:
            if cap_s < timeout_s:
                raise _not_graded(start, timeout_s, "a cache hit")
            raise AssertionError(
                f"never observed a cache hit (repeated reqId) within {timeout_s:.0f}s of the "
                f"300s TTL; last seen {baseline!r}"
            )
        time.sleep(2.0)


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_backend_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-flushcache-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_backend_lambda(ctx) -> str:
    """A Lambda backend that returns a fresh UUID on every real invocation, so a cache hit
    (which skips the backend) is observable as a repeated value -- see _BACKEND_CODE."""
    role_arn = _create_backend_role(ctx)
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-flushcache-fn-")
    code = _zip_bytes(_BACKEND_CODE)

    deadline = time.monotonic() + 60.0
    resp = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        if lam.get_function_configuration(FunctionName=fn_name)["State"] == "Active":
            break
        time.sleep(3.0)
    else:
        raise AssertionError(f"lambda function {fn_name} never became Active")
    return resp["FunctionArn"]


def _allow_apigateway_invoke(ctx, function_arn: str, source_arn: str) -> None:
    lam = ctx.client("lambda")
    fn_name = function_arn.split(":")[-1]
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
