"""flush-stage-cache-without-cluster-succeeds-as-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "flush-stage-cache-without-cluster-succeeds-as-noop"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushStageCache on a stage without a cache cluster succeeds as a no-op, leaving the stage untouched."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-flushnocache-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "prod"
    # cacheClusterEnabled intentionally omitted (defaults to disabled) - there is no cluster to flush.
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)

    before = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert before.get("cacheClusterEnabled", False) is False
    before_status = before.get("cacheClusterStatus")
    before_last_updated = before["lastUpdatedDate"]

    # Real AWS does not reject this call: with no cache cluster provisioned, FlushStageCache is
    # simply a no-op that succeeds without ever enabling or otherwise touching the cache cluster.
    resp = apigw.flush_stage_cache(restApiId=api_id, stageName=stage_name)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 202
    payload_keys = [k for k in resp.keys() if k != "ResponseMetadata"]
    assert payload_keys == [], f"expected an empty success payload, got keys {payload_keys}"

    after = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert after.get("cacheClusterEnabled", False) is False, "flush without a cluster must not enable one"
    assert after.get("cacheClusterStatus") == before_status, "no-op flush must not alter cache cluster status"
    assert after["deploymentId"] == deployment_id
    assert after["lastUpdatedDate"] == before_last_updated, (
        f"a true no-op must not bump lastUpdatedDate: before={before_last_updated!r} "
        f"after={after['lastUpdatedDate']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
