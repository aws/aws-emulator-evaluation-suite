"""flush-stage-cache-without-cache-enabled-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "flush-stage-cache-without-cache-enabled-accepted"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushStageCache on a stage that never enabled a cache cluster is a permissive no-op on
    real AWS: there is no server-managed cache to flush, so the call succeeds (200/202) rather
    than being rejected, and it must not have the side effect of provisioning a cache cluster."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-nocache-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="nocache")["id"]
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

    stage_name = "nocachetest"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    # FlushStageCache on a stage that has never had a cache cluster enabled does NOT raise
    # BadRequestException. There is no server-managed cache to flush, so the operation is a
    # permissive no-op that succeeds with a 200/202 response. The meaningful server-side invariant to assert
    # is that this "flush nothing" call is accepted without error *and* that it has no
    # side effect of provisioning/enabling a cache cluster on the stage.
    flush_resp = apigw.flush_stage_cache(restApiId=api_id, stageName=stage_name)
    assert flush_resp["ResponseMetadata"]["HTTPStatusCode"] in (200, 202), (
        f"expected FlushStageCache on a cache-less stage to be accepted as a no-op, "
        f"got HTTP {flush_resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage.get("cacheClusterEnabled") is not True, (
        "flushing a non-existent cache must not have the side effect of enabling one"
    )
    assert stage.get("cacheClusterStatus") in (None, "NOT_AVAILABLE"), (
        f"flushing a non-existent cache must not provision a cache cluster, "
        f"got cacheClusterStatus={stage.get('cacheClusterStatus')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
