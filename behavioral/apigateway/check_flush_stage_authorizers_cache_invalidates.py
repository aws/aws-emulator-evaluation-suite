"""flush-stage-authorizers-cache-invalidates."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flush-stage-authorizers-cache-invalidates"
GROUP = 'deployments-stages'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushStageAuthorizersCache succeeds twice on a stage with a TTL>0 authorizer.

    It leaves the method's authorizer wiring intact, and an unknown stageName is rejected with
    NotFoundException without disturbing the real stage.
    """
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="secure")["id"]

    authorizer = ag.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("auth-"),
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"arn:aws:lambda:{ctx.region}:123456789012:function:dummy/invocations"
        ),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=300,
    )
    authorizer_id = authorizer["id"]
    ag.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(restApiId=api_id, stageName="prod", deploymentId=deployment_id)

    # Both calls must succeed: a ClientError from either fails the check.
    ag.flush_stage_authorizers_cache(restApiId=api_id, stageName="prod")
    ag.flush_stage_authorizers_cache(restApiId=api_id, stageName="prod")

    # The cache flush must not have altered the method's authorizer wiring.
    method_after = ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert method_after.get("authorizerId") == authorizer_id, (
        "FlushStageAuthorizersCache must only invalidate the cache, not the method's authorizer wiring"
    )

    # Overly-permissive boundary: an unknown stageName must be rejected.
    bad_stage_code, bad_stage_message = _error(
        lambda: ag.flush_stage_authorizers_cache(
            restApiId=api_id, stageName="sim2real-behav-no-such-stage"
        )
    )
    assert bad_stage_code == "NotFoundException", (
        f"expected NotFoundException flushing the authorizer cache of an unknown stage, got {bad_stage_code}"
    )
    assert bad_stage_message == "Invalid stage identifier specified", (
        f"unexpected NotFoundException message {bad_stage_message!r}"
    )

    # The rejected call must have had no effect on the real stage or its authorizer wiring.
    stage_after = ag.get_stage(restApiId=api_id, stageName="prod")
    assert stage_after["stageName"] == "prod", (
        "the real stage must remain resolvable after an unknown-stage flush attempt"
    )
    method_final = ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert method_final.get("authorizerId") == authorizer_id, (
        "an unknown-stage flush attempt must not disturb the real stage's authorizer wiring"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
