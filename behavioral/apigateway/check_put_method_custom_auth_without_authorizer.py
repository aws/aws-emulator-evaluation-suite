"""put-method-custom-auth-without-authorizer."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-method-custom-auth-without-authorizer"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMethod with authorizationType=CUSTOM but no authorizerId must fail (overly-permissive check)."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="secure")["id"]

    code, message = _error(
        lambda: ag.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            authorizationType="CUSTOM",
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for CUSTOM auth without authorizerId, got {code}"
    )
    assert message == (
        'Invalid authorizer ID specified. Setting the authorization type to CUSTOM or COGNITO_USER_POOLS requires a valid authorizer.'
    ), f"unexpected {code} message: {message!r}"

    # Effect absent: the rejected PutMethod left no method behind.
    get_code, get_code_message = _error(
        lambda: ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    )
    assert get_code == "NotFoundException", (
        f"a method exists despite the rejected PutMethod, got {get_code}"
    )
    assert get_code_message == (
        'Invalid Method identifier specified'
    ), f"unexpected {get_code} message: {get_code_message!r}"

    # Positive control: the identical operation on the same resource succeeds
    # once authorizationType no longer demands an authorizerId.
    ag.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )
    created = ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert created["authorizationType"] == "NONE", (
        f"expected NONE, got {created.get('authorizationType')}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
