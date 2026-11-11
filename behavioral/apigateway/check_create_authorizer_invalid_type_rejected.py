"""create-authorizer-invalid-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-authorizer-invalid-type-rejected"
GROUP = "negative-classes"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAuthorizer with a type value outside the TOKEN/REQUEST/COGNITO_USER_POOLS enum is
    rejected server-side and no authorizer is created, while a valid TOKEN authorizer on the
    same API succeeds."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-restapi-"), tags={"sim2real": CHECK}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    bad_name = "BadAuthorizer"
    # botocore does not client-side validate enum membership (forward compatibility), so this
    # request round-trips to the real service and must be rejected there.
    code, message = _error(
        lambda: apigw.create_authorizer(
            restApiId=api_id,
            name=bad_name,
            type="NOT_A_REAL_TYPE",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Invalid AuthorizerType specified.", f"unexpected BadRequestException message {message!r}"

    # effect-absent: no authorizer was created on the API.
    authorizers = apigw.get_authorizers(restApiId=api_id)["items"]
    assert not any(a.get("name") == bad_name for a in authorizers), "an authorizer was created with an invalid type"

    # positive control: a valid TOKEN authorizer on the same API succeeds.
    region = ctx.region
    lambda_uri = (
        f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{region}:123456789012:function:dummy-authorizer-fn/invocations"
    )
    created = apigw.create_authorizer(
        restApiId=api_id,
        name="GoodAuthorizer",
        type="TOKEN",
        authorizerUri=lambda_uri,
        identitySource="method.request.header.Authorization",
    )
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=created["id"]))
    assert created["type"] == "TOKEN", f"expected type TOKEN, got {created['type']!r}"

    fetched = apigw.get_authorizer(restApiId=api_id, authorizerId=created["id"])
    assert fetched["name"] == "GoodAuthorizer", f"expected name GoodAuthorizer, got {fetched['name']!r}"


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
