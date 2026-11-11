"""delete-authorizer-attached-to-method-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-authorizer-attached-to-method-conflict"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")

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
    """Deleting an authorizer still referenced by a method must fail with ConflictException (overly-permissive check)."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    authorizer_name = ctx.unique_name("sim2real-behav-authz-")
    created = ag.create_authorizer(
        restApiId=api_id,
        name=authorizer_name,
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"arn:aws:lambda:{ctx.region}:123456789012:function:dummy/invocations"
        ),
        identitySource="method.request.header.Authorization",
    )
    authorizer_id = created["id"]

    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="secure")["id"]
    ag.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )

    code, message = _error(
        lambda: ag.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    )
    assert code == "ConflictException", (
        f"expected ConflictException deleting an authorizer attached to a method, got {code}"
    )
    assert message == (
        f"Cannot delete authorizer '{authorizer_name}', is referenced in method: GET//secure"
    ), f"unexpected in-use message: {message!r}"

    # Effect absent: the rejected delete must not have removed the authorizer.
    still_there = ag.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert still_there["id"] == authorizer_id, (
        f"authorizer should survive a rejected delete, got {still_there!r}"
    )

    # Release the reference so the authorizer can actually be deleted.
    ag.delete_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    ag.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id)

    # Positive control: the identical call now succeeds, and an independent read confirms it.
    code_after, message_after = _error(
        lambda: ag.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    )
    assert code_after == "NotFoundException", (
        f"expected NotFoundException reading a deleted authorizer, got {code_after}"
    )
    assert message_after == "Invalid Authorizer identifier specified", f"unexpected not-found message: {message_after!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
