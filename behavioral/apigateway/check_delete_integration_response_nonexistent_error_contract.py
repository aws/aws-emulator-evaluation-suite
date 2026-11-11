"""delete-integration-response-nonexistent-error-contract."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-integration-response-nonexistent-error-contract"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIntegrationResponse for a never-created status code "404" fails with NotFoundException
    "Invalid Response status code specified" and leaves the existing "200" response; deleting "200"
    then succeeds and a later GET of it fails with NotFoundException."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = _root_resource_id(apigw, api_id)
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200", responseTemplates={}
    )

    code, message = _client_error(
        lambda: apigw.delete_integration_response(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="404"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException deleting a never-created response, got {code}"
    assert message == "Invalid Response status code specified", f"expected the generic status-code-invalid message, got {message!r}"

    # Effect absent: the real "200" integration response must be untouched.
    still_there = apigw.get_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    assert still_there["statusCode"] == "200", f"expected the '200' response to survive, got {still_there!r}"

    # Positive control: deleting the response that actually exists succeeds and persists.
    apigw.delete_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    code_after, message_after = _client_error(
        lambda: apigw.get_integration_response(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
        )
    )
    assert code_after == "NotFoundException", f"expected the deleted '200' response to be gone, got {code_after}"
    assert message_after == "Invalid Response status code specified", f"unexpected not-found message: {message_after!r}"


def _root_resource_id(apigw: Any, api_id: str) -> str:
    for item in apigw.get_resources(restApiId=api_id)["items"]:
        if item["path"] == "/":
            return item["id"]
    raise AssertionError("root resource not found")


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return (err.response["Error"]["Code"], err.response["Error"].get("Message", ""))
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
