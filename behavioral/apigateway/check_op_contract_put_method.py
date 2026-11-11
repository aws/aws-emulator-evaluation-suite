"""op-contract-putMethod."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-putMethod"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMethod persists a method definition on a resource; CUSTOM auth without an authorizerId -> BadRequestException."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]

    created = apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
        apiKeyRequired=True,
    )
    assert created["httpMethod"] == "GET", f"expected httpMethod GET, got {created['httpMethod']!r}"
    assert created["authorizationType"] == "NONE", (
        f"expected authorizationType NONE, got {created['authorizationType']!r}"
    )
    assert created["apiKeyRequired"] is True, (
        f"expected apiKeyRequired True, got {created['apiKeyRequired']!r}"
    )

    persisted = apigw.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert persisted["authorizationType"] == "NONE", (
        f"persisted authorizationType diverged from creation: expected NONE, got "
        f"{persisted['authorizationType']!r}"
    )
    assert persisted["apiKeyRequired"] is True, (
        f"persisted apiKeyRequired diverged from creation: expected True, got "
        f"{persisted['apiKeyRequired']!r}"
    )

    code, message = _error(
        lambda: apigw.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            authorizationType="CUSTOM",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        'Invalid authorizer ID specified. Setting the authorization type to CUSTOM or COGNITO_USER_POOLS requires a valid authorizer.'
    ), f"unexpected {code} message: {message!r}"

    # the malformed POST method must not have been created
    not_found_code, not_found_code_message = _error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="POST")
    )
    assert not_found_code == "NotFoundException", (
        f"rejected CUSTOM-without-authorizerId method should not persist, "
        f"expected NotFoundException on GetMethod, got {not_found_code!r}"
    )
    assert not_found_code_message == (
        'Invalid Method identifier specified'
    ), f"unexpected {not_found_code} message: {not_found_code_message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
