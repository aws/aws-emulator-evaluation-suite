"""flush-stage-authorizers-cache-clears-authorizer-cache."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flush-stage-authorizers-cache-clears-authorizer-cache"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """FlushStageAuthorizersCache succeeds idempotently and leaves the stage's deployed config
    untouched, and rejects a stage name that does not exist on the API rather than silently
    no-op-succeeding."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-flushauth-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authorizer-"),
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"arn:aws:lambda:{ctx.region}:123456789012:function:placeholder/invocations"
        ),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=300,
    )["id"]

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)

    before = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert before["deploymentId"] == deployment_id, (
        f"expected the stage's deployment to be {deployment_id!r} before any flush, "
        f"got {before['deploymentId']!r}"
    )

    resp1 = apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)
    payload_keys = [k for k in resp1.keys() if k != "ResponseMetadata"]
    assert payload_keys == [], f"expected an empty success payload, got keys {payload_keys}"
    assert resp1["ResponseMetadata"]["HTTPStatusCode"] == 202, (
        f"expected HTTP 202 Accepted from FlushStageAuthorizersCache, "
        f"got {resp1['ResponseMetadata']['HTTPStatusCode']}"
    )

    # The call is idempotent: repeating it also succeeds without altering deployed stage config.
    resp2 = apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)
    assert resp2["ResponseMetadata"]["HTTPStatusCode"] == 202, (
        f"expected a second FlushStageAuthorizersCache call to also return HTTP 202, "
        f"got {resp2['ResponseMetadata']['HTTPStatusCode']}"
    )

    after = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert after["deploymentId"] == deployment_id, (
        f"flushing the authorizer cache must not change the deployment: expected "
        f"{deployment_id!r}, got {after['deploymentId']!r}"
    )

    # Break exactly one precondition: an unknown stage name on the same, real API. The forbidden
    # effect (any mutation tied to the bogus stage) must not happen, so the real stage's deployed
    # config stays exactly as asserted above.
    missing_stage = ctx.unique_name("no-such-stage-")
    code, message = _error(
        lambda: apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=missing_stage)
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException flushing the authorizer cache of an unknown stage "
        f"{missing_stage!r}, got {code!r}"
    )
    assert message == "Invalid stage identifier specified", (
        f"unexpected NotFoundException message {message!r}"
    )

    unaffected = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert unaffected["deploymentId"] == deployment_id, (
        f"the rejected flush against a bogus stage must leave the real stage's deployment "
        f"untouched: expected {deployment_id!r}, got {unaffected['deploymentId']!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
