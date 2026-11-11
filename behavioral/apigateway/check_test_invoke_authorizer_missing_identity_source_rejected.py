"""test-invoke-authorizer-missing-identity-source-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "test-invoke-authorizer-missing-identity-source-rejected"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestInvokeAuthorizer rejects a simulated request that lacks the authorizer's required
    identitySource header, before ever attempting to invoke the backing function."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-authz-neg-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    region = ctx.region
    # A nonexistent function ARN suffices because identity-source validation precedes invocation; the
    # ARN carries the caller's own account id, because a foreign one changes how the call is evaluated.
    account_id = sts.get_caller_identity()["Account"]
    function_name = "sim2real-nonexistent"
    authorizer_uri = (
        f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{region}:{account_id}:function:{function_name}/invocations"
    )
    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authorizer-neg-"),
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))

    # TestInvokeAuthorizer raises no ClientError for a request lacking the identitySource: it reports
    # clientStatus 401 in its response, with a log that never mentions the backing function.
    response = apigw.test_invoke_authorizer(restApiId=api_id, authorizerId=authorizer_id, headers={})
    client_status = response.get("clientStatus")
    assert client_status == 401, (
        f"expected the simulated clientStatus for a missing identity source to be 401, "
        f"got {client_status!r} (full response: {response!r})"
    )
    missing_log = response.get("log", "")
    assert function_name not in missing_log, (
        f"backing function {function_name!r} should never have been invoked without an identity "
        f"source, but the execution log references it: {missing_log!r}"
    )
    assert not response.get("principalId"), (
        f"authorizer's backing function should never have been invoked without an identity "
        f"source, but got principalId={response.get('principalId')!r}"
    )
    assert not response.get("policy"), "no authorization policy should be produced without an identity source"

    # Positive control: with the identity source header present API Gateway attempts the invocation,
    # which fails differently (the function does not exist) with a log that references the function.
    present = apigw.test_invoke_authorizer(
        restApiId=api_id, authorizerId=authorizer_id, headers={"Authorization": "sim2real-test-token"}
    )
    present_log = present.get("log", "")
    assert function_name in present_log, (
        f"expected an actual invocation attempt against {function_name!r} once the identity "
        f"source header is present, but the log does not reference it: {present_log!r}"
    )
    assert present.get("clientStatus") != client_status, (
        f"expected a different clientStatus once the identity source header is present (an "
        f"invocation attempt against a nonexistent function) than with it missing (never "
        f"invoked), got {present.get('clientStatus')!r} in both cases"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
