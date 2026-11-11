"""authorizer-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorizer-lifecycle"
GROUP = 'authorizers'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAuthorizer -> GetAuthorizer reflects fields -> DeleteAuthorizer removes it."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)
    name = ctx.unique_name("sim2real-behav-authorizer-")

    created = ag.create_authorizer(
        restApiId=rest_api_id,
        name=name,
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"arn:aws:lambda:{ctx.region}:123456789012:function:auth/invocations"
        ),
        identitySource="method.request.header.Authorization",
    )
    authorizer_id = created["id"]

    got = ag.get_authorizer(restApiId=rest_api_id, authorizerId=authorizer_id)
    assert got["name"] == name, f"expected name {name!r}, got {got.get('name')!r}"
    assert got["type"] == "TOKEN", f"expected type TOKEN, got {got.get('type')!r}"

    ag.delete_authorizer(restApiId=rest_api_id, authorizerId=authorizer_id)
    code, message = _error(
        lambda: ag.get_authorizer(restApiId=rest_api_id, authorizerId=authorizer_id)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Authorizer identifier specified", f"unexpected message {message!r}"

    # the dead id is not just unreadable, it is unusable for mutation too
    code, message = _error(
        lambda: ag.update_authorizer(
            restApiId=rest_api_id,
            authorizerId=authorizer_id,
            patchOperations=[{"op": "replace", "path": "/name", "value": "whatever"}],
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Authorizer identifier specified", f"unexpected message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
