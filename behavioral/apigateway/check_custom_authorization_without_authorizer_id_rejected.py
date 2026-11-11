"""custom-authorization-without-authorizer-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-authorization-without-authorizer-id-rejected"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMethod rejects authorizationType=CUSTOM without an authorizerId and persists nothing;
    CUSTOM with a real authorizerId succeeds (isolating the missing id), as does a NONE method."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-customauth-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    code, message = _error(
        lambda: apigw.put_method(
            restApiId=api_id, resourceId=root_id, httpMethod="DELETE", authorizationType="CUSTOM"
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = (
        "Invalid authorizer ID specified. Setting the authorization type to CUSTOM or "
        "COGNITO_USER_POOLS requires a valid authorizer."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="DELETE")
    )
    assert code == "NotFoundException", (
        f"the rejected CUSTOM-without-authorizerId method should not have persisted, "
        f"but GetMethod returned {code!r}"
    )
    expected = "Invalid Method identifier specified"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-customauth-authz-"),
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"arn:aws:lambda:{ctx.region}:123456789012:function:auth/invocations"
        ),
        identitySource="method.request.header.Authorization",
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))

    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="PUT",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    # DeleteAuthorizer refuses while a method references the authorizer, so the method goes first.
    ctx.on_cleanup(lambda: apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="PUT"))
    custom_ok = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="PUT")
    assert custom_ok["authorizationType"] == "CUSTOM", (
        f"expected CUSTOM, got {custom_ok.get('authorizationType')!r}"
    )
    assert custom_ok.get("authorizerId") == authorizer_id, (
        f"expected authorizerId {authorizer_id!r}, got {custom_ok.get('authorizerId')!r}"
    )

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    control = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert control["authorizationType"] == "NONE", (
        f"expected NONE, got {control.get('authorizationType')!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
