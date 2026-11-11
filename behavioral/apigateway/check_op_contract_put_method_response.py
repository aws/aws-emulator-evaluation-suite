"""op-contract-putMethodResponse."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-putMethodResponse"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMethodResponse creates a response model for a statusCode; a duplicate statusCode -> ConflictException."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"),
        tags={"sim2real": "op-contract-putMethodResponse"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="things")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")

    created = apigw.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseModels={"application/json": "Empty"},
    )
    assert created["statusCode"] == "200"
    assert created["responseModels"] == {"application/json": "Empty"}

    persisted = apigw.get_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    assert persisted["responseModels"] == {"application/json": "Empty"}

    # positive control: a distinct statusCode is accepted without conflict
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="404"
    )

    code, message = _error(
        lambda: apigw.put_method_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            statusCode="200",
            responseModels={"application/json": "Error"},
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == (
        'Response already exists for this resource'
    ), f"unexpected {code} message: {message!r}"

    # the conflicting PutMethodResponse must not have overwritten the original response model
    unchanged = apigw.get_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    assert unchanged["responseModels"] == {"application/json": "Empty"}


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
