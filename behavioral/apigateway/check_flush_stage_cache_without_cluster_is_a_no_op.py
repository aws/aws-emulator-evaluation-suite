"""flush-stage-cache-without-cluster-is-a-no-op."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flush-stage-cache-without-cluster-is-a-no-op"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushStageCache on a stage whose cacheClusterEnabled is left at False succeeds with an empty
    2xx response, not a BadRequestException, and the stage's cacheClusterEnabled stays False."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-nocache-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    stage_name = "sim"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    stage = _poll_until(
        lambda: apigw.get_stage(restApiId=api_id, stageName=stage_name),
        lambda s: s.get("cacheClusterEnabled", False) is False,
        timeout_s=60.0,
        interval_s=3.0,
        what="newly created stage to be visible with caching disabled",
    )
    assert stage.get("cacheClusterEnabled", False) is False

    result = _flush_with_retry(
        lambda: apigw.flush_stage_cache(restApiId=api_id, stageName=stage_name),
    )
    assert not isinstance(result, str), f"expected FlushStageCache to succeed as a no-op, got error {result!r}"
    assert result["ResponseMetadata"]["HTTPStatusCode"] in (200, 202), (
        f"expected a success status for a no-op flush, got HTTP {result['ResponseMetadata']['HTTPStatusCode']}"
    )
    payload_keys = [k for k in result if k != "ResponseMetadata"]
    assert payload_keys == [], f"expected an empty success payload, got keys {payload_keys}"

    # No side effect: the stage must still report no cache cluster afterward.
    after = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert after.get("cacheClusterEnabled", False) is False, (
        f"FlushStageCache must not enable a cache cluster; got {after.get('cacheClusterEnabled')!r}"
    )


def _poll_until(probe, predicate, timeout_s: float, interval_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {what}; last={last!r}")


def _flush_with_retry(fn, *, max_attempts: int = 8, base_delay: float = 2.0):
    """Invoke fn(), returning its response on success or the error code (str) on terminal failure.

    Immediately after CreateDeployment, the newly minted stage can be subject
    to brief propagation lag (NotFoundException) or to account-level control
    plane throttling (TooManyRequestsException) on real AWS; both are
    transient and unrelated to the semantic outcome under test (that
    FlushStageCache on a cache-less stage succeeds as a no-op). Retry through
    those transient codes with backoff so the deterministic outcome can be
    observed.
    """
    attempt = 0
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            attempt += 1
            if code in ("NotFoundException", "TooManyRequestsException") and attempt < max_attempts:
                time.sleep(base_delay * attempt)
                continue
            return code


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

