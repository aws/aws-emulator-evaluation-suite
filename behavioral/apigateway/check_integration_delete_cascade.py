"""integration-delete-cascade."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "integration-delete-cascade"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting an integration response then the integration clears GetIntegration, leaving the method intact."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={"sim2real": "true"}
    )["id"]
    ctx.on_cleanup(lambda: _best_effort(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": ""},
    )

    integration = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert integration["type"] == "MOCK", f"expected MOCK, got {integration['type']!r}"
    assert "200" in integration["integrationResponses"], (
        f"expected integration response 200 present, got {list(integration['integrationResponses'])}"
    )

    apigw.delete_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    integration_after_response_delete = apigw.get_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET"
    )
    assert integration_after_response_delete["type"] == "MOCK", "integration should still exist"
    assert "integrationResponses" not in integration_after_response_delete or not integration_after_response_delete[
        "integrationResponses"
    ], "integration response should be gone"

    apigw.delete_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")

    code, message = _error(
        lambda: apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Integration identifier specified", f"unexpected message {message!r}"

    # DeleteIntegration on an already-deleted integration is a no-op success (measured on real
    # AWS: it does not raise NotFoundException); the resource must not be resurrected by it.
    apigw.delete_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    still_gone_code, still_gone_message = _error(
        lambda: apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert still_gone_code == "NotFoundException", (
        f"a double-deleted integration must not have been resurrected, got {still_gone_code}"
    )
    assert still_gone_message == "Invalid Integration identifier specified", (
        f"unexpected message {still_gone_message!r}"
    )

    method = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert method["httpMethod"] == "GET", f"expected GET, got {method['httpMethod']!r}"
    assert method["authorizationType"] == "NONE", (
        f"expected authorizationType NONE, got {method['authorizationType']!r}"
    )
    assert "methodIntegration" not in method or method["methodIntegration"] is None, (
        f"expected no methodIntegration on the method after integration delete, got {method.get('methodIntegration')!r}"
    )


def _error(fn):
    """Call fn(); return the ClientError's (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
