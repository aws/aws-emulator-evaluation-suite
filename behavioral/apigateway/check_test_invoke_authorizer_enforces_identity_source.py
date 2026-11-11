"""test-invoke-authorizer-enforces-identity-source."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "test-invoke-authorizer-enforces-identity-source"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestInvokeAuthorizer without the configured identitySource answers clientStatus 401 with a
    log that never references the authorizer function, while with it present the log does: the
    identity source is validated before any invocation."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"),
        tags={"sim2real": "test-invoke-authorizer-enforces-identity-source"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # a syntactically valid but non-existent Lambda authorizer target: CreateAuthorizer
    # only validates ARN shape, so this is enough to isolate the identitySource check.
    fake_lambda_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:function:sim2real-nonexistent-authorizer"
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fake_lambda_arn}/invocations"
    )
    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authorizer-"),
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))

    # Without the identitySource header TestInvokeAuthorizer raises no ClientError: its response
    # reports clientStatus 401, and the authorizer function is never invoked.
    resp_missing = apigw.test_invoke_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert resp_missing.get("clientStatus") == 401, (
        f"expected clientStatus 401 when the identitySource header is missing, "
        f"got {resp_missing.get('clientStatus')!r}"
    )
    # The log always carries some bookkeeping lines, so only the function name is a reliable
    # invocation signal: it appears once API Gateway tries to invoke the function.
    missing_log = resp_missing.get("log", "")
    assert "sim2real-nonexistent-authorizer" not in missing_log, (
        f"expected no invocation attempt against the authorizer function when identitySource "
        f"is missing, but the log references the function: {missing_log!r}"
    )

    # With identitySource present API Gateway attempts the invocation and fails differently (the
    # function does not exist), so the identitySource check runs first and gates invocation.
    resp = apigw.test_invoke_authorizer(
        restApiId=api_id,
        authorizerId=authorizer_id,
        headers={"Authorization": "some-test-token"},
    )
    assert resp.get("clientStatus") != 200, (
        "authorizer invocation against a nonexistent Lambda function unexpectedly reported success"
    )
    log = resp.get("log", "")
    assert log, "expected TestInvokeAuthorizer to report an invocation log once identitySource is present"
    assert "sim2real-nonexistent-authorizer" in log, (
        f"expected the log to reference the (nonexistent) authorizer function once identitySource "
        f"is present, proving an invocation was actually attempted, got {log!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
