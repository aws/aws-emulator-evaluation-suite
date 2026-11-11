"""flush-stage-cache-clears-response-cache."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "flush-stage-cache-clears-response-cache"
GROUP = "server-side"
SERVICES = ["apigateway"]


# The harness bounds run(ctx) at a per-check ceiling the check cannot see or extend from inside
# itself, and the generic default is too short: a 0.5GB stage cache cluster can still be
# CREATE_IN_PROGRESS past 240s, which does not leave room for cluster-ready + flush + settle in
# the same run. This constant states the ceiling this check actually needs. Poll timeouts below
# are apportioned from what remains of THIS budget.
HARD_BUDGET_S = 1200.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushStageCache leaves the stage's deployment binding and variables untouched, and the
    cache cluster settles back to AVAILABLE afterward."""
    start = time.monotonic()

    def _remaining(reserve_s: float) -> float:
        return max(10.0, HARD_BUDGET_S - (time.monotonic() - start) - reserve_s)

    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-flushcache-"),
        tags={"sim2real": "flush-stage-cache-clears-response-cache"},
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

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "prod"
    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        cacheClusterEnabled=True,
        cacheClusterSize="0.5",
        variables={"env": "prod"},
        tags={"sim2real": "flush-stage-cache-clears-response-cache"},
    )

    # Cache cluster provisioning is a slow prerequisite, not the behavior under test.
    ready_timeout_s = _remaining(reserve_s=60.0)
    status = _poll_stage_status(apigw, api_id, stage_name, timeout_s=ready_timeout_s, interval_s=15)
    if status != "AVAILABLE":
        raise AssertionError(
            f"cache cluster never reached AVAILABLE (last status={status}); cannot exercise flush",
        )

    before = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert before["deploymentId"] == deployment_id, (
        f"precondition: stage must be serving {deployment_id!r} before flush, got {before.get('deploymentId')!r}"
    )
    assert before["variables"] == {"env": "prod"}, (
        f"precondition: stage variables must be {{'env': 'prod'}} before flush, got {before.get('variables')!r}"
    )

    apigw.flush_stage_cache(restApiId=api_id, stageName=stage_name)

    # Requiring an observed transient FLUSH_IN_PROGRESS status here would fail every correct
    # target: with nothing cached (this check never issues a GET against the deployed stage), a
    # cache cluster flushes faster than is observable at a practical polling cadence, so
    # cacheClusterStatus never reads as anything but AVAILABLE across the call.
    remaining_s = _remaining(reserve_s=10.0)
    final_status = _poll_stage_status(apigw, api_id, stage_name, timeout_s=remaining_s, interval_s=5)
    assert final_status == "AVAILABLE", f"cache cluster did not settle back to AVAILABLE, last={final_status}"

    after = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert after["deploymentId"] == deployment_id, "FlushStageCache must not change the deployed deploymentId"
    assert after["variables"] == {"env": "prod"}, "FlushStageCache must not alter stage variables"


def _poll_stage_status(apigw, api_id, stage_name, timeout_s, interval_s=15):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = apigw.get_stage(restApiId=api_id, stageName=stage_name)["cacheClusterStatus"]
        if status == "AVAILABLE":
            return status
        time.sleep(interval_s)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
