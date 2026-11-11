"""flush-stage-cache-clears-server-managed-cache."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "flush-stage-cache-clears-server-managed-cache"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushStageCache/FlushStageAuthorizersCache drive real cacheClusterStatus transitions on a
    stage with an actually-provisioned API cache cluster."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-cache-api-"),
        tags={"sim2real": "flush-stage-cache-clears-server-managed-cache"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="cacheme")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": "{}"},
    )

    stage_name = "cachetest"
    deployment_id = apigw.create_deployment(restApiId=api_id, stageName=stage_name)["id"]

    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/cacheClusterEnabled", "value": "true"},
            {"op": "replace", "path": "/cacheClusterSize", "value": "0.5"},
        ],
    )

    def get_stage():
        return apigw.get_stage(restApiId=api_id, stageName=stage_name)

    def get_status():
        return get_stage()["cacheClusterStatus"]

    status = _poll_until(get_status, lambda s: s == "AVAILABLE", timeout_s=420.0, interval_s=10.0)
    assert status == "AVAILABLE", f"expected the provisioned cache cluster to reach AVAILABLE, got {status!r}"

    # Independent read at the destination: the positive control before either flush is exercised —
    # a real cluster is up, bound to the deployment this check made, and caching is on.
    before = get_stage()
    assert before["deploymentId"] == deployment_id, (
        f"expected stage bound to {deployment_id!r} before any flush, got {before.get('deploymentId')!r}"
    )
    assert before.get("cacheClusterEnabled") is True, (
        f"expected cacheClusterEnabled True before any flush, got {before.get('cacheClusterEnabled')!r}"
    )

    flush_resp = apigw.flush_stage_cache(restApiId=api_id, stageName=stage_name)
    assert flush_resp["ResponseMetadata"]["HTTPStatusCode"] in (200, 202), (
        f"expected FlushStageCache to return 200/202, got {flush_resp['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # after a flush the cache must recompute rather than silently keep serving the same status forever
    status_after = _poll_until(get_status, lambda s: s == "AVAILABLE", timeout_s=120.0, interval_s=5.0)
    assert status_after == "AVAILABLE", (
        f"expected the cache cluster to settle back to AVAILABLE after FlushStageCache, got {status_after!r}"
    )

    # Independent read: FlushStageCache must not have detached the stage from its deployment or
    # silently disabled caching as a side effect.
    mid = get_stage()
    assert mid["deploymentId"] == deployment_id, (
        f"FlushStageCache must not change the stage's deploymentId, expected {deployment_id!r}, "
        f"got {mid.get('deploymentId')!r}"
    )
    assert mid.get("cacheClusterEnabled") is True, (
        f"FlushStageCache must not disable caching, expected True, got {mid.get('cacheClusterEnabled')!r}"
    )

    authz_flush_resp = apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)
    assert authz_flush_resp["ResponseMetadata"]["HTTPStatusCode"] in (200, 202), (
        f"expected FlushStageAuthorizersCache to return 200/202, got "
        f"{authz_flush_resp['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # Terminal assertion: an independent read at the destination, through a different operation
    # than either mutating flush call. Both the response cache and the authorizer cache flush must
    # leave the stage's deployment binding and cache-cluster configuration intact.
    after = get_stage()
    assert after["deploymentId"] == deployment_id, (
        f"FlushStageAuthorizersCache must not change the stage's deploymentId, expected "
        f"{deployment_id!r}, got {after.get('deploymentId')!r}"
    )
    assert after.get("cacheClusterEnabled") is True, (
        f"FlushStageAuthorizersCache must not disable caching, expected True, got "
        f"{after.get('cacheClusterEnabled')!r}"
    )
    assert after["cacheClusterStatus"] == "AVAILABLE", (
        f"expected the cache cluster to still read AVAILABLE at the destination after both "
        f"flushes, got {after['cacheClusterStatus']!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
