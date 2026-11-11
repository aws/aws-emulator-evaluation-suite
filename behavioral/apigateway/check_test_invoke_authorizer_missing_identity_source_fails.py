"""test-invoke-authorizer-missing-identity-source-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "test-invoke-authorizer-missing-identity-source-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestInvokeAuthorizer without the identity source returns 200 with the rejection in
    clientStatus, no principalId and no function invocation in the log; with the header present
    the (nonexistent) function is referenced, so the identity-source check gates invocation."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-authz-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    account_id = sts.get_caller_identity()["Account"]
    fake_lambda_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:function:sim2real-fidelity-nonexistent"
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fake_lambda_arn}/invocations"
    )

    authorizer = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authorizer-"),
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )
    authorizer_id = authorizer["id"]

    listed = apigw.get_authorizers(restApiId=api_id)["items"]
    assert any(item["id"] == authorizer_id for item in listed), (
        f"expected authorizer {authorizer_id!r} to appear in GetAuthorizers, got ids "
        f"{[item['id'] for item in listed]!r}"
    )

    # Negative: identity source header absent -> short-circuited before any invocation attempt.
    missing = apigw.test_invoke_authorizer(restApiId=api_id, authorizerId=authorizer_id, headers={})
    assert missing.get("clientStatus") != 200, (
        f"expected a non-200 simulated clientStatus when the identity source header is missing, "
        f"got {missing.get('clientStatus')!r} (full response: {missing!r})"
    )
    assert not missing.get("principalId"), (
        f"backing function must not be invoked without the identity source, but got "
        f"principalId={missing.get('principalId')!r}"
    )
    missing_log = missing.get("log", "")
    assert "sim2real-fidelity-nonexistent" not in missing_log, (
        f"expected no invocation attempt against the backing function when the identity source "
        f"is missing, but the log references it: {missing_log!r}"
    )

    # Positive control: with the identity source header present, API Gateway proceeds to (attempt
    # to) invoke the backing function -- a materially different failure mode (the function does
    # not exist) than the short-circuit above, proving the identity source check specifically
    # gates invocation rather than TestInvokeAuthorizer rejecting every call.
    present = apigw.test_invoke_authorizer(
        restApiId=api_id,
        authorizerId=authorizer_id,
        headers={"Authorization": "sim2real-test-token"},
    )
    assert present.get("clientStatus") != 200, (
        "authorizer invocation against a nonexistent Lambda function unexpectedly reported success"
    )
    present_log = present.get("log", "")
    assert "sim2real-fidelity-nonexistent" in present_log, (
        f"expected the log to reference the backing function once the identity source header is "
        f"present, proving an invocation was actually attempted, got {present_log!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
