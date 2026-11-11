"""authorizer-missing-uri-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorizer-missing-uri-fails"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAuthorizer of type TOKEN without authorizerUri must fail with BadRequestException,
    and no authorizer is created (overly-permissive check). An otherwise-identical request with
    authorizerUri present succeeds (positive control, same file)."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)

    bad_name = ctx.unique_name("sim2real-behav-bad-authorizer-")
    code, message = _expect_rejected(
        lambda: ag.create_authorizer(
            restApiId=rest_api_id,
            name=bad_name,
            type="TOKEN",
            identitySource="method.request.header.Authorization",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "URI is a required field in an Authorizer", f"unexpected message {message!r}"

    # Effect absent: no authorizer was created on the API.
    names = {a["name"] for a in ag.get_authorizers(restApiId=rest_api_id).get("items", [])}
    assert bad_name not in names, "an authorizer was created despite the missing authorizerUri"

    # Positive control: an otherwise-identical request with authorizerUri present succeeds.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{ctx.region}:{account_id}:function:sim2real-behav-fake/invocations"
    )
    good_name = ctx.unique_name("sim2real-behav-good-authorizer-")
    created = ag.create_authorizer(
        restApiId=rest_api_id,
        name=good_name,
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
    )
    authorizer_id = created["id"]
    ctx.on_cleanup(lambda: ag.delete_authorizer(restApiId=rest_api_id, authorizerId=authorizer_id))
    assert created["type"] == "TOKEN", f"expected TOKEN, got {created['type']}"

    # Independent read at the destination: confirm get_authorizer agrees, not just the mutating
    # call's own response.
    fetched = ag.get_authorizer(restApiId=rest_api_id, authorizerId=authorizer_id)
    assert fetched["name"] == good_name, f"expected name {good_name!r}, got {fetched['name']!r}"
    assert fetched["authorizerUri"] == authorizer_uri, (
        f"expected authorizerUri {authorizer_uri!r}, got {fetched['authorizerUri']!r}"
    )


def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


def _expect_rejected(fn):
    """Call fn(); return its (error code, message), or raise if it unexpectedly succeeded."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
