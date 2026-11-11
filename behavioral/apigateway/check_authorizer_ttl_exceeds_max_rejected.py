"""authorizer-ttl-exceeds-max-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorizer-ttl-exceeds-max-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAuthorizer rejects authorizerResultTtlInSeconds above the 3600s maximum."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    region = ctx.region
    account_id = sts.get_caller_identity()["Account"]

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-ttlmax-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    dummy_fn_arn = f"arn:aws:lambda:{region}:{account_id}:function:sim2real-nonexistent-authorizer"
    authorizer_uri = f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{dummy_fn_arn}/invocations"

    bad_name = ctx.unique_name("sim2real-badttl-")
    code, message = _error(
        lambda: apigw.create_authorizer(
            restApiId=api_id,
            name=bad_name,
            type="TOKEN",
            authorizerUri=authorizer_uri,
            identitySource="method.request.header.Authorization",
            authorizerResultTtlInSeconds=3601,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Authorizer result TTL outside allowable range. TTL must be between 0 and 3600 seconds.", (
        f"unexpected message {message!r}"
    )

    # Effect absent: the rejected CreateAuthorizer must not have created anything.
    names = {a["name"] for a in apigw.get_authorizers(restApiId=api_id)["items"]}
    assert bad_name not in names, "rejected CreateAuthorizer (ttl=3601) must not have created the resource"

    # Positive control: the same authorizer at the boundary (3600s) is accepted.
    good_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-okttl-"),
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=3600,
    )["id"]

    # Terminal read is independent of the mutating call: fetch the authorizer back.
    fetched = apigw.get_authorizer(restApiId=api_id, authorizerId=good_id)
    assert fetched["authorizerResultTtlInSeconds"] == 3600, (
        f"expected stored ttl 3600, got {fetched.get('authorizerResultTtlInSeconds')!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
