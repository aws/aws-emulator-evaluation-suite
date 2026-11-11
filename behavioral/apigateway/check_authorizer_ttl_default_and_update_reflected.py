"""authorizer-ttl-default-and-update-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "authorizer-ttl-default-and-update-reflected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """authorizerResultTtlInSeconds defaults to 300 when omitted, UpdateAuthorizer changes are
    visible immediately, and TestInvokeAuthorizer reports clientStatus=500 when API Gateway
    cannot invoke the configured Lambda authorizer."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-authttl-"),
        tags={"sim2real": "authorizer-ttl-default-and-update-reflected"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    lambda_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-nonexistent-authorizer/invocations"
    )

    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-behav-authz-"),
        type="TOKEN",
        authorizerUri=lambda_uri,
        identitySource="method.request.header.Authorization",
    )["id"]

    # When omitted on create, GetAuthorizer returns no TTL key and the documented
    # default of 300s applies implicitly; treat an absent key as the default.
    created = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    created_ttl = created.get("authorizerResultTtlInSeconds", 300)
    assert created_ttl == 300, (
        f"expected AWS default TTL of 300s (explicit or implicit via omitted field), got {created_ttl}"
    )

    apigw.update_authorizer(
        restApiId=api_id,
        authorizerId=authorizer_id,
        patchOperations=[{"op": "replace", "path": "/authorizerResultTtlInSeconds", "value": "0"}],
    )
    disabled = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert disabled["authorizerResultTtlInSeconds"] == 0, (
        f"expected ttl=0 to be reflected immediately, got {disabled.get('authorizerResultTtlInSeconds')}"
    )

    apigw.update_authorizer(
        restApiId=api_id,
        authorizerId=authorizer_id,
        patchOperations=[{"op": "replace", "path": "/authorizerResultTtlInSeconds", "value": "120"}],
    )
    updated = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert updated["authorizerResultTtlInSeconds"] == 120, (
        f"expected ttl=120 to be reflected after update, got {updated.get('authorizerResultTtlInSeconds')}"
    )

    # The target function does not exist, so API Gateway cannot invoke it and reports 500.
    invoke_result = apigw.test_invoke_authorizer(
        restApiId=api_id,
        authorizerId=authorizer_id,
        headers={"Authorization": "test-token"},
        pathWithQueryString="/",
    )
    assert invoke_result["clientStatus"] == 500, (
        f"expected clientStatus 500 for an unreachable Lambda authorizer, got {invoke_result.get('clientStatus')}"
    )
    assert invoke_result["log"], "expected a non-empty execution log describing the invocation failure"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
