"""put-method-response-invalid-model-reference-rejected."""
from __future__ import annotations

from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-method-response-invalid-model-reference-rejected"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMethodResponse validates referenced model names server-side before accepting the response."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")

    bogus_model_name = "NoSuchModelXYZ123"
    code, message = _error(lambda: apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseModels={"application/json": bogus_model_name},
    ))
    assert code == "BadRequestException", (
        f"expected BadRequestException for a nonexistent model reference, got {code!r}"
    )
    assert message == f"Invalid model identifier specified: {bogus_model_name}", (
        f"unexpected message: {message!r}"
    )

    absent_code, absent_message = _error(lambda: apigw.get_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
    ))
    assert absent_code == "NotFoundException", (
        "the rejected PutMethodResponse must not have created a method response"
    )
    assert absent_message == "Invalid Response status code specified", (
        f"unexpected message: {absent_message!r}"
    )

    # Positive control: referencing the always-present built-in "Empty" model succeeds.
    apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseModels={"application/json": "Empty"},
    )
    response = apigw.get_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    assert response["responseModels"] == {"application/json": "Empty"}, (
        f"expected responseModels {{'application/json': 'Empty'}} after the positive-control "
        f"PutMethodResponse, got {response.get('responseModels')!r}"
    )


def _error(fn: Callable[[], object]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
