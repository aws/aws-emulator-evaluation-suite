"""put-integration-response-invalid-content-handling-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-integration-response-invalid-content-handling-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIntegrationResponse with a contentHandling outside the enum fails ValidationException and
    stores nothing, while a valid contentHandling is accepted and persisted (positive control)."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    code, message = _error(
        lambda: apigw.put_integration_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            statusCode="200",
            contentHandling="NOT_A_REAL_CONTENT_HANDLING",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'NOT_A_REAL_CONTENT_HANDLING' at 'putIntegrationResponseInput.contentHandling' failed to satisfy constraint: Member must satisfy enum value set: [CONVERT_TO_TEXT, CONVERT_TO_BINARY]"
    ), f"unexpected {code} message: {message!r}"

    not_found_code, not_found_code_message = _error(
        lambda: apigw.get_integration_response(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
        )
    )
    assert not_found_code == "NotFoundException", (
        f"expected no integration response stored after rejection, got {not_found_code!r}"
    )
    assert not_found_code_message == (
        'Invalid Response status code specified'
    ), f"unexpected {not_found_code} message: {not_found_code_message!r}"

    # Positive control: a valid contentHandling value is accepted and persisted.
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        contentHandling="CONVERT_TO_TEXT",
        responseTemplates={"application/json": '{"ok": true}'},
    )
    fetched = apigw.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert fetched["contentHandling"] == "CONVERT_TO_TEXT", (
        f"expected contentHandling CONVERT_TO_TEXT to persist, got {fetched.get('contentHandling')!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
