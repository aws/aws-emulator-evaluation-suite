"""delete-authorizer-in-use-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-authorizer-in-use-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAuthorizer must be rejected with ConflictException while a method
    still references the authorizer via authorizerId."""
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-authinuse-")
    api_id = apigw.create_rest_api(name=api_name, tags={"Name": api_name})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    authorizer_name = ctx.unique_name("sim2real-authorizer-")
    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=authorizer_name,
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-fake/invocations"
        ),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )

    code, message = _error(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))
    assert code == "ConflictException", f"expected ConflictException while authorizer is referenced, got {code!r}"
    assert message == (
        f"Cannot delete authorizer '{authorizer_name}', is referenced in method: GET//"
    ), f"unexpected in-use message: {message!r}"

    # Effect absent: the rejected delete must not have removed the authorizer.
    still_there = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert still_there["id"] == authorizer_id, f"expected authorizer to survive the rejected delete, got {still_there}"

    # Once the reference is removed, the same delete must succeed.
    apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    code_after, message_after = _error(lambda: apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id))
    assert code_after == "NotFoundException", code_after
    assert message_after == "Invalid Authorizer identifier specified", (
        f"unexpected not-found message: {message_after!r}"
    )


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
