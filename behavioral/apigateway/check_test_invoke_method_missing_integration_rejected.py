"""test-invoke-method-missing-integration-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-invoke-method-missing-integration-rejected"
GROUP = "server-side"
SERVICES = ["apigateway"]

_MOCK_REQUEST_TEMPLATES = {"application/json": '{"statusCode": 200}'}
_MOCK_RESPONSE_TEMPLATES = {"application/json": '{"message": "ok"}'}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestInvokeMethod on a method with no integration fails with BadRequestException.
    The same call serves 200 with a MOCK integration before deletion and after restore,
    so the rejection is attributable to the missing integration alone.
    """
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-noint-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = _root_resource_id(apigw, api_id)
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="bare")
    resource_id = resource["id"]

    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    # PutMethodResponse is create-only (a second call for the same status code raises
    # ConflictException), so it is set up once here and left alone across the later
    # delete/restore of the integration, which does not touch it.
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )

    # Positive control: with a MOCK integration wired up, TestInvokeMethod serves a real 200.
    _put_mock_integration(apigw, api_id, resource_id)
    control = apigw.test_invoke_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", pathWithQueryString="/bare"
    )
    assert control["status"] == 200, (
        f"positive control: expected the wired-up MOCK integration to serve 200, "
        f"got {control.get('status')!r}"
    )

    apigw.delete_integration(restApiId=api_id, resourceId=resource_id, httpMethod="GET")

    absent = _client_error(
        lambda: apigw.get_integration(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    )
    assert absent.get("Code") == "NotFoundException", (
        f"expected GetIntegration to report the deleted integration gone with "
        f"NotFoundException, got {absent.get('Code')!r}"
    )
    assert absent.get("Message") == "Invalid Integration identifier specified", (
        f"expected the exact missing-integration message from GetIntegration, got {absent.get('Message')!r}"
    )

    err = _client_error(
        lambda: apigw.test_invoke_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            pathWithQueryString="/bare",
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "No integration defined for method", (
        f"expected the exact no-integration refusal message, got {err.get('Message')!r}"
    )

    _put_mock_integration(apigw, api_id, resource_id)
    restored = apigw.test_invoke_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", pathWithQueryString="/bare"
    )
    assert restored["status"] == 200, (
        f"after restoring the integration, expected the identical call to succeed with 200, "
        f"got {restored.get('status')!r}"
    )


def _root_resource_id(apigw, api_id: str) -> str:
    resources = apigw.get_resources(restApiId=api_id)["items"]
    for r in resources:
        if r["path"] == "/":
            return r["id"]
    raise AssertionError("root resource not found")


def _put_mock_integration(apigw, api_id: str, resource_id: str) -> None:
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates=_MOCK_REQUEST_TEMPLATES,
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates=_MOCK_RESPONSE_TEMPLATES,
    )


def _client_error(fn):
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
