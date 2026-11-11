"""flush-stage-cache-invalidates-managed-cache."""
from __future__ import annotations

import random
import string
import time

from behavioral_harness import tags

CHECK = "flush-stage-cache-invalidates-managed-cache"
GROUP = 'deployments-stages'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id.

    Tagged so a tag search finds it if the run dies before cleanup."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _quick_stage(ag, api_id, stage_name="prod"):
    """Wire a minimal MOCK method + deployment + stage on api_id (cascades away
    with the parent RestApi's tracked delete). Returns the deploymentId."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=f"r{_unique_token()}"
    )["id"]
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        type="MOCK", requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    return deployment_id

def _wait_cache_cluster_status(ag, api_id, stage_name, target_statuses, timeout_s=600, interval_s=5):
    """Poll get_stage until cacheClusterStatus lands in target_statuses (or timeout)."""
    deadline = time.time() + timeout_s
    status = None
    while True:
        status = ag.get_stage(restApiId=api_id, stageName=stage_name).get("cacheClusterStatus")
        if status in target_statuses or time.time() >= deadline:
            return status
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushStageCache on a cached stage leaves its deploymentId and caching untouched and the
    cluster settles back to AVAILABLE, and on a stage with no cache cluster it is a no-op that
    does not enable caching (the flush is non-disruptive, not a redeploy)."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    deployment_id = _quick_stage(ag, api_id, "prod")

    no_cache_stage = ag.get_stage(restApiId=api_id, stageName="prod")
    assert not no_cache_stage.get("cacheClusterEnabled"), "expected caching disabled by default"

    # FlushStageCache on a stage with no active cache cluster succeeds as a no-op (there is
    # nothing to invalidate; a ClientError fails the check) and must NOT have the side effect
    # of enabling a cache cluster.
    ag.flush_stage_cache(restApiId=api_id, stageName="prod")
    still_no_cache = ag.get_stage(restApiId=api_id, stageName="prod")
    assert not still_no_cache.get("cacheClusterEnabled"), (
        "a no-op FlushStageCache on an uncached stage must not have implicitly enabled caching"
    )

    ag.update_stage(
        restApiId=api_id,
        stageName="prod",
        patchOperations=[
            {"op": "replace", "path": "/cacheClusterEnabled", "value": "true"},
            {"op": "replace", "path": "/cacheClusterSize", "value": "0.5"},
        ],
    )
    # Provisioning a real Elasticache-backed stage cache cluster can take minutes.
    available = _wait_cache_cluster_status(ag, api_id, "prod", ("AVAILABLE",), timeout_s=600)
    assert available == "AVAILABLE", f"expected cache cluster to reach AVAILABLE, got {available!r}"

    # No new deployment — FlushStageCache alone must invalidate the managed cache.
    still_bound = ag.get_stage(restApiId=api_id, stageName="prod")
    assert still_bound["deploymentId"] == deployment_id, "flushing the cache must not touch the stage's deploymentId"

    ag.flush_stage_cache(restApiId=api_id, stageName="prod")
    settled = _wait_cache_cluster_status(ag, api_id, "prod", ("AVAILABLE",), timeout_s=600)
    assert settled == "AVAILABLE", (
        f"expected the cache cluster to settle back to AVAILABLE after FlushStageCache, got {settled!r}"
    )
    after_flush = ag.get_stage(restApiId=api_id, stageName="prod")
    assert after_flush["deploymentId"] == deployment_id, (
        "FlushStageCache must not have required (or implicitly performed) a redeploy"
    )
    assert after_flush.get("cacheClusterEnabled") is True, "caching must remain enabled after a flush"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
