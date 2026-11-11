"""stage-cache-ttl-configuration-enforced."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stage-cache-ttl-configuration-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A method-level cacheTtlInSeconds set with UpdateStage reads back from GetStage and survives a
    FlushStageCache unchanged, with caching still enabled and the cache cluster back to AVAILABLE."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-cachettl-"),
        tags={"sim2real": CHECK},
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
        # Provisioning an API Gateway cache cluster can take several minutes.
        timeout_s=600,
        interval_s=5,
    )

    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/*/*/caching/enabled", "value": "true"},
            {"op": "replace", "path": "/*/*/caching/ttlInSeconds", "value": "301"},
        ],
    )

    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    settings = stage["methodSettings"]["*/*"]
    assert settings["cachingEnabled"] is True, f"expected cachingEnabled=True, got {settings!r}"
    assert settings["cacheTtlInSeconds"] == 301, settings

    apigw.flush_stage_cache(restApiId=api_id, stageName=stage_name)

    _poll_until(
        lambda: apigw.get_stage(restApiId=api_id, stageName=stage_name)["cacheClusterStatus"],
        lambda status: status == "AVAILABLE",
        # Provisioning an API Gateway cache cluster can take several minutes.
        timeout_s=600,
        interval_s=5,
    )

    stage_after_flush = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    settings_after = stage_after_flush["methodSettings"]["*/*"]
    assert settings_after["cacheTtlInSeconds"] == 301, "TTL config should survive a cache flush"
    assert settings_after["cachingEnabled"] is True, (
        f"expected cachingEnabled=True after flush, got {settings_after!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
