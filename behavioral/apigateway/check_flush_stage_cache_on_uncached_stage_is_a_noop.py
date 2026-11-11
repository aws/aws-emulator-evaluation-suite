"""flush-stage-cache-on-uncached-stage-is-a-noop."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "flush-stage-cache-on-uncached-stage-is-a-noop"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushStageCache on a stage with caching disabled succeeds as a no-op and does not enable
    caching; FlushStageAuthorizersCache on the same stage also succeeds, because the authorizer
    result cache exists regardless of response caching."""
    apigw = ctx.client("apigateway")
    api = _minimal_deployed_api(ctx)

    # A no-op success: a ClientError fails the check.
    apigw.flush_stage_cache(restApiId=api["id"], stageName=api["stage"])
    after = apigw.get_stage(restApiId=api["id"], stageName=api["stage"])
    assert after.get("cacheClusterEnabled", False) is False, (
        "a no-op flush must not enable response caching as a side effect"
    )

    # distinct subsystem: authorizer cache flush is independent of cacheClusterEnabled
    authz_resp = apigw.flush_stage_authorizers_cache(restApiId=api["id"], stageName=api["stage"])
    assert authz_resp["ResponseMetadata"]["HTTPStatusCode"] in (200, 202), (
        f"FlushStageAuthorizersCache must succeed regardless of stage response caching, "
        f"got HTTP {authz_resp['ResponseMetadata']['HTTPStatusCode']}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _minimal_deployed_api(ctx) -> dict:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-cache-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))
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
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    return {"id": api_id, "stage": stage_name}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
