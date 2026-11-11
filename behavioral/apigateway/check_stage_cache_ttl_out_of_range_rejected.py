"""stage-cache-ttl-out-of-range-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stage-cache-ttl-out-of-range-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStage rejects a cacheTtlInSeconds value outside the valid
    0-3600 second range with BadRequestException, and the stage's prior
    (valid) TTL configuration is left untouched by the rejected attempt.
    """
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-cachettlneg-"), tags={"sim2real": CHECK}
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
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]

    stage_name = "sim2realbehav"
    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        cacheClusterEnabled=True,
        cacheClusterSize="0.5",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    _poll_until(
        lambda: apigw.get_stage(restApiId=api_id, stageName=stage_name)["cacheClusterStatus"],
        lambda status: status == "AVAILABLE",
        # Provisioning a real API Gateway cache cluster commonly takes several
        # minutes (observed >180s on real AWS), well beyond dev-mode latency.
        timeout_s=600,
        interval_s=5,
    )

    # establish a known-good baseline TTL first
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/*/*/caching/enabled", "value": "true"},
            {"op": "replace", "path": "/*/*/caching/ttlInSeconds", "value": "120"},
        ],
    )

    def _attempt_out_of_range():
        apigw.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {"op": "replace", "path": "/*/*/caching/ttlInSeconds", "value": "3601"},
            ],
        )

    code, message = _error(_attempt_out_of_range)
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Invalid time-to-live setting, must be an integer no greater than 3600", (
        f"unexpected message: {message!r}"
    )

    # the rejected attempt must not have mutated the previously-valid setting
    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    ttl_after_rejection = stage["methodSettings"]["*/*"]["cacheTtlInSeconds"]
    assert ttl_after_rejection == 120, (
        f"expected the pre-rejection TTL of 120 to survive untouched, got {ttl_after_rejection!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _error(fn):
    """Call fn() and return its botocore (Code, Message). An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
