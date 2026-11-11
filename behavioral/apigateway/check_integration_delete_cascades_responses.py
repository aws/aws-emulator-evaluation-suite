"""integration-delete-cascades-responses."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "integration-delete-cascades-responses"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIntegration also removes its integration responses; Update* patch settings in place."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-intcascade-")
    rest_api_id = apigw.create_rest_api(name=name)["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]

    apigw.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
        timeoutInMillis=10000,
    )
    apigw.put_method_response(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": "initial-template"},
    )

    # UpdateIntegration patches settings in place (same resourceId/httpMethod identity).
    apigw.update_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        patchOperations=[{"op": "replace", "path": "/timeoutInMillis", "value": "15000"}],
    )
    patched_integration = apigw.get_integration(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET")
    assert patched_integration["timeoutInMillis"] == 15000, (
        f"expected timeoutInMillis patched to 15000, got {patched_integration.get('timeoutInMillis')!r}"
    )
    assert patched_integration["type"] == "MOCK", (
        f"UpdateIntegration must patch in place, not replace identity; expected type MOCK, "
        f"got {patched_integration.get('type')!r}"
    )

    # UpdateIntegrationResponse patches settings in place.
    apigw.update_integration_response(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        patchOperations=[
            {"op": "replace", "path": "/responseTemplates/application~1json", "value": "patched-template"}
        ],
    )
    patched_response = apigw.get_integration_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert patched_response["responseTemplates"]["application/json"] == "patched-template", (
        f"expected responseTemplates patched to 'patched-template', "
        f"got {patched_response.get('responseTemplates')!r}"
    )

    apigw.delete_integration(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET")

    integration_code, integration_message = _error(
        lambda: apigw.get_integration(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET")
    )
    assert integration_code == "NotFoundException", f"expected NotFoundException, got {integration_code!r}"
    assert integration_message == "Invalid Integration identifier specified", (
        f"unexpected message {integration_message!r}"
    )

    response_code, response_message = _error(
        lambda: apigw.get_integration_response(
            restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
        )
    )
    assert response_code == "NotFoundException", (
        f"deleting the integration must cascade-delete its integration responses, got {response_code!r}"
    )
    assert response_message == "Invalid Integration identifier specified", (
        f"unexpected message {response_message!r}"
    )

    # The method and its method response survive the integration deletion.
    surviving_method = apigw.get_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET")
    assert surviving_method["httpMethod"] == "GET", (
        f"deleting the integration must not remove the method, got {surviving_method.get('httpMethod')!r}"
    )
    surviving_response = apigw.get_method_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert surviving_response["statusCode"] == "200", (
        f"deleting the integration must not remove the method response, "
        f"got {surviving_response.get('statusCode')!r}"
    )


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return the ClientError's (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
