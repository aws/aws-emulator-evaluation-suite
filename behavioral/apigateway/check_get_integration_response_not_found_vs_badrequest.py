"""get-integration-response-not-found-vs-badrequest."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "get-integration-response-not-found-vs-badrequest"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIntegrationResponse returns NotFoundException for both an unknown status code on an
    existing integration and an unknown method, each with its own exact message, so a target
    that collapses both into one generic 404 is caught."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"),
        tags={"sim2real": "get-integration-response-not-found-vs-badrequest"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = _root_resource_id(apigw, api_id)
    resource_id = apigw.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="items"
    )["id"]

    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        responseTemplates={},
    )

    # Positive control: the response we actually created is fetchable.
    control = apigw.get_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    assert control["statusCode"] == "200", f"expected positive control to return 200, got {control!r}"

    # Case A: existing method+integration, but the "404" response was never created.
    code_a, msg_a = _client_error_and_message(
        lambda: apigw.get_integration_response(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="404"
        )
    )
    # Case B: the HTTP method itself was never defined on this resource at all.
    code_b, msg_b = _client_error_and_message(
        lambda: apigw.get_integration_response(
            restApiId=api_id, resourceId=resource_id, httpMethod="DELETE", statusCode="200"
        )
    )

    assert code_a == "NotFoundException", f"expected NotFoundException for missing status code, got {code_a}"
    assert code_b == "NotFoundException", f"expected NotFoundException for missing method, got {code_b}"
    assert msg_a == "Invalid Response status code specified", f"unexpected message A: {msg_a!r}"
    assert msg_b == "Invalid Integration identifier specified", f"unexpected message B: {msg_b!r}"


def _root_resource_id(apigw: Any, api_id: str) -> str:
    for item in apigw.get_resources(restApiId=api_id)["items"]:
        if item["path"] == "/":
            return item["id"]
    raise AssertionError("root resource not found")


def _client_error_and_message(fn: Callable[[], Any]) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (err.response["Error"]["Code"], err.response["Error"].get("Message", ""))
    raise AssertionError(f"expected a NotFoundException, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
