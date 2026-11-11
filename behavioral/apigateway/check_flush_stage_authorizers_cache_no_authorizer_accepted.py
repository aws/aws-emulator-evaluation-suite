"""flush-stage-authorizers-cache-no-authorizer-accepted."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flush-stage-authorizers-cache-no-authorizer-accepted"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushStageAuthorizersCache on a stage with no cacheable authorizer succeeds (202) without
    raising ConflictException, and leaves the stage's deployment and the method's authorization
    unchanged."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-noauthcache-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = _root_resource_id(apigw, api_id)
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="open")
    resource_id = resource["id"]

    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )

    stage_name = "nocache"
    deployment_id = apigw.create_deployment(restApiId=api_id, stageName=stage_name)["id"]
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    # Real AWS treats FlushStageAuthorizersCache as an idempotent no-op when the target stage has
    # no cacheable authorizer configured: it succeeds rather than raising ConflictException. Like
    # the sibling FlushStageCache action, a successful call returns 202 Accepted (no body), not 200.
    try:
        response = apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)
    except ClientError as exc:
        raise AssertionError(
            f"flush_stage_authorizers_cache unexpectedly failed on a stage with no cacheable "
            f"authorizer: {exc.response['Error']}"
        ) from exc
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 202, response

    # Calling it again is still a harmless no-op (idempotent, not stateful rejection).
    response2 = apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)
    assert response2["ResponseMetadata"]["HTTPStatusCode"] == 202, response2

    # Independent read at the destination, through different operations than the mutating flush:
    # the no-op must not have altered the stage's deployment or the method's authorization wiring.
    stage_after = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage_after["deploymentId"] == deployment_id, (
        f"flushing a nonexistent authorizer cache must not change the stage's deployment, "
        f"expected {deployment_id}, got {stage_after['deploymentId']}"
    )

    method_after = apigw.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert method_after.get("authorizationType") == "NONE", (
        f"flushing a nonexistent authorizer cache must not attach an authorizer, "
        f"got authorizationType={method_after.get('authorizationType')!r}"
    )


def _root_resource_id(apigw, api_id: str) -> str:
    resources = apigw.get_resources(restApiId=api_id)["items"]
    for r in resources:
        if r["path"] == "/":
            return r["id"]
    raise AssertionError("root resource not found")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
