"""integration-response-delete-removes-response."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "integration-response-delete-removes-response"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIntegrationResponse creates a status-code mapping; DeleteIntegrationResponse removes it (404 after)."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-intresp-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": "sim2real-template"},
    )

    got = apigw.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert got["responseTemplates"]["application/json"] == "sim2real-template"

    apigw.delete_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    code, message = _error(
        lambda: apigw.get_integration_response(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Response status code specified", f"unexpected message {message!r}"

    # A mutation on the now-dead status code fails too, not just the read.
    update_code, update_message = _error(
        lambda: apigw.update_integration_response(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
            patchOperations=[{"op": "replace", "path": "/responseTemplates/application~1json", "value": "x"}],
        )
    )
    assert update_code == "NotFoundException", f"expected NotFoundException on update, got {update_code}"
    assert update_message == "Invalid Response status code specified", f"unexpected message {update_message!r}"

    # The parent integration survives; only its 200 response mapping is gone.
    integration = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert integration["type"] == "MOCK"
    assert "200" not in integration.get("integrationResponses", {})

    # The status code is reusable, not permanently retired by the delete.
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": "sim2real-recreated"},
    )
    recreated = apigw.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert recreated["responseTemplates"]["application/json"] == "sim2real-recreated"


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
