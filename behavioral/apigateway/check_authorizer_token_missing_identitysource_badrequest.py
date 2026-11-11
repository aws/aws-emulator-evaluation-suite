"""authorizer-token-missing-identitysource-badrequest."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorizer-token-missing-identitysource-badrequest"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "authorizer-missing-identitysource"},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAuthorizer of type TOKEN without identitySource fails with BadRequestException and
    creates nothing; the same call with identitySource on the same API succeeds."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    region = ctx.region
    authorizer_uri = (
        f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{region}:123456789012:function:fake/invocations"
    )

    bad_name = ctx.unique_name("sim2real-behav-authz-")
    code, message = _error(
        lambda: ag.create_authorizer(
            restApiId=api_id,
            name=bad_name,
            type="TOKEN",
            authorizerUri=authorizer_uri,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Invalid request input", f"unexpected message {message!r}"

    authorizers = ag.get_authorizers(restApiId=api_id)["items"]
    assert not any(a.get("name") == bad_name for a in authorizers), (
        "an authorizer was created despite the missing identitySource being rejected"
    )

    good_name = ctx.unique_name("sim2real-behav-authz-ok-")
    created = ag.create_authorizer(
        restApiId=api_id,
        name=good_name,
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
    )
    ctx.on_cleanup(lambda: ag.delete_authorizer(restApiId=api_id, authorizerId=created["id"]))
    assert created["type"] == "TOKEN", f"expected type TOKEN, got {created.get('type')!r}"

    fetched = ag.get_authorizer(restApiId=api_id, authorizerId=created["id"])
    assert fetched["name"] == good_name, f"expected {good_name!r}, got {fetched.get('name')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
