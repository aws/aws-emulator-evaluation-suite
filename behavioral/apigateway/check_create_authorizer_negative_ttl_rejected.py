"""create-authorizer-negative-ttl-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-authorizer-negative-ttl-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAuthorizer with a negative authorizerResultTtlInSeconds fails with BadRequestException and
    creates no authorizer, while the same request with a valid TTL succeeds."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real": "create-authorizer-negative-ttl-rejected"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    account_id = _account_id(ctx)
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{ctx.region}:{account_id}:function:sim2real-behav-fake/invocations"
    )

    bad_name = ctx.unique_name("sim2real-behav-authz-bad-")
    code, message = _error(
        lambda: apigw.create_authorizer(
            restApiId=api_id,
            name=bad_name,
            type="TOKEN",
            authorizerUri=authorizer_uri,
            identitySource="method.request.header.Authorization",
            authorizerResultTtlInSeconds=-1,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        "Authorizer result TTL outside allowable range. TTL must be between 0 and 3600 "
        "seconds."
    ), f"unexpected BadRequestException message {message!r}"

    # Effect absent: no authorizer of this name was created on the API.
    names = {a["name"] for a in apigw.get_authorizers(restApiId=api_id).get("items", [])}
    assert bad_name not in names, (
        f"rejected CreateAuthorizer must not have created {bad_name!r}, but it appears in "
        f"GetAuthorizers: {names!r}"
    )

    # Positive control: a valid, non-negative TTL is accepted.
    good_name = ctx.unique_name("sim2real-behav-authz-good-")
    created = apigw.create_authorizer(
        restApiId=api_id,
        name=good_name,
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=300,
    )
    authorizer_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))

    fetched = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert fetched["authorizerResultTtlInSeconds"] == 300, (
        f"expected the positive control's TTL to be 300, got "
        f"{fetched.get('authorizerResultTtlInSeconds')!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
