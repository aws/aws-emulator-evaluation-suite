"""flush-stage-authorizers-cache-rejects-missing-stage."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "flush-stage-authorizers-cache-rejects-missing-stage"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """FlushStageAuthorizersCache accepts (202) a real stage that has a cached
    CUSTOM authorizer attached, but rejects a stage name that does not exist on
    the API with NotFoundException, leaving the real stage's cache untouched."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-flushauth-"),
        tags={"sim2real": "flush-stage-authorizers-cache-rejects-missing-stage"},
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-behav-authz-"),
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-nonexistent/invocations"
        ),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=300,
    )["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "test"
    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        tags={"sim2real": "flush-stage-authorizers-cache-rejects-missing-stage"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name)))

    # Positive control: a real stage with a cached CUSTOM authorizer accepts the flush.
    ok_resp = apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)
    assert ok_resp["ResponseMetadata"]["HTTPStatusCode"] == 202, (
        f"expected FlushStageAuthorizersCache on a real stage to return 202, "
        f"got {ok_resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    # Break exactly one precondition: an unknown stage name on the same, real API.
    missing_stage = ctx.unique_name("no-such-stage-")
    code, message = _error(
        lambda: apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=missing_stage)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid stage identifier specified", (
        f"unexpected NotFoundException message {message!r}"
    )

    # The forbidden effect (any mutation tied to the bogus stage) did not happen:
    # the real stage is unaffected and still resolvable.
    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage["stageName"] == stage_name, (
        f"expected the real stage {stage_name!r} to remain resolvable after the rejected "
        f"flush against a missing stage, got {stage.get('stageName')!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return its botocore (Error Code, Error Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
