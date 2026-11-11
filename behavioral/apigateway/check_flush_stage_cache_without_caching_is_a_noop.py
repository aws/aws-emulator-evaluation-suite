"""flush-stage-cache-without-caching-is-a-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "flush-stage-cache-without-caching-is-a-noop"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushStageCache on a stage created without cacheClusterEnabled returns 200 and leaves the
    stage untouched (no cache cluster, unchanged lastUpdatedDate); FlushStageAuthorizersCache
    succeeds on the same stage."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-api-"),
        tags={"sim2real": "flush-stage-cache-without-caching-is-a-noop"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # CreateDeployment rejects a REST API with no methods, so a minimal MOCK GET on the root resource
    # is the cheapest deployable shape; its own behavior is not under test.
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "prod"
    stage = apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))
    assert "cacheClusterStatus" not in stage or stage["cacheClusterStatus"] == "NOT_AVAILABLE", (
        f"a freshly created stage with no cacheClusterEnabled must report no cache cluster, "
        f"got cacheClusterStatus={stage.get('cacheClusterStatus')!r}"
    )

    before = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    before_last_updated = before["lastUpdatedDate"]
    before_cache_status = before.get("cacheClusterStatus")

    # On real AWS, with `cacheClusterEnabled: False`, FlushStageCache returns 200 and does
    # nothing: a no-op, NOT a rejection (a ClientError fails the check). The no-mutation legs
    # below are what make the no-op falsifiable.
    apigw.flush_stage_cache(restApiId=api_id, stageName=stage_name)

    # ...and being a no-op, it must not have mutated the stage at all.
    after = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert after["lastUpdatedDate"] == before_last_updated, (
        f"FlushStageCache is a no-op and must not bump lastUpdatedDate: "
        f"before={before_last_updated!r} after={after['lastUpdatedDate']!r}"
    )
    assert after.get("cacheClusterStatus") == before_cache_status, (
        f"FlushStageCache must not change cache cluster status on a cluster-less stage: "
        f"before={before_cache_status!r} after={after.get('cacheClusterStatus')!r}"
    )

    # Positive control: the SAME stage accepts FlushStageAuthorizersCache, proving the no-op above
    # is specific to the absent response-cache cluster rather than a broader setup or permission
    # problem with this stage -- i.e. that the 200 means "nothing to flush", not "nothing works".
    ok_resp = apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)
    assert ok_resp["ResponseMetadata"]["HTTPStatusCode"] == 202, (
        f"FlushStageAuthorizersCache on the same cache-less stage must still succeed, "
        f"got HTTP {ok_resp['ResponseMetadata']['HTTPStatusCode']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
