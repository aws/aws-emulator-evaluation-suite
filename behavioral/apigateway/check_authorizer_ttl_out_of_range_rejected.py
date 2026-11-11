"""authorizer-ttl-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "authorizer-ttl-out-of-range-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]

_TTL_RANGE_MESSAGE = "Authorizer result TTL outside allowable range. TTL must be between 0 and 3600 seconds."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """authorizerResultTtlInSeconds is capped at 3600: 3600 is accepted, while 3601 is rejected with
    BadRequestException naming the bound on both CreateAuthorizer and UpdateAuthorizer, without
    changing the stored TTL; a valid UpdateAuthorizer TTL patch still takes effect."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-ttlrange-"),
        tags={"sim2real": "authorizer-ttl-out-of-range-rejected"},
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
        authorizerResultTtlInSeconds=3600,
    )["id"]
    fetched = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert fetched["authorizerResultTtlInSeconds"] == 3600, (
        f"expected TTL 3600 at creation, got {fetched['authorizerResultTtlInSeconds']}"
    )

    code, message = _client_error(
        lambda: apigw.update_authorizer(
            restApiId=api_id,
            authorizerId=authorizer_id,
            patchOperations=[{"op": "replace", "path": "/authorizerResultTtlInSeconds", "value": "3601"}],
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException on update, got {code}"
    assert message == _TTL_RANGE_MESSAGE, f"expected the 3600s bound named in the message, got: {message!r}"
    unchanged = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert unchanged["authorizerResultTtlInSeconds"] == 3600, (
        f"TTL changed to {unchanged['authorizerResultTtlInSeconds']} despite the rejected update"
    )

    apigw.update_authorizer(
        restApiId=api_id,
        authorizerId=authorizer_id,
        patchOperations=[{"op": "replace", "path": "/authorizerResultTtlInSeconds", "value": "1800"}],
    )
    patched = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert patched["authorizerResultTtlInSeconds"] == 1800, (
        f"expected the valid TTL patch to take effect, got {patched['authorizerResultTtlInSeconds']}"
    )

    bogus_name = ctx.unique_name("sim2real-behav-authz-oob-")
    code, message = _client_error(
        lambda: apigw.create_authorizer(
            restApiId=api_id,
            name=bogus_name,
            type="TOKEN",
            authorizerUri=lambda_uri,
            identitySource="method.request.header.Authorization",
            authorizerResultTtlInSeconds=3601,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException on create, got {code}"
    assert message == _TTL_RANGE_MESSAGE, f"expected the 3600s bound named in the message, got: {message!r}"
    names = {a["name"] for a in apigw.get_authorizers(restApiId=api_id)["items"]}
    assert bogus_name not in names, "rejected CreateAuthorizer must not have created the resource"



def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
