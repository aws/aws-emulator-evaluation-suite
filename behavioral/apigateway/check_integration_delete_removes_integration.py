"""integration-delete-removes-integration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "integration-delete-removes-integration"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIntegration attaches a MOCK integration to a method; DeleteIntegration removes it (404 after)."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-integ-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    got = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert got["type"] == "MOCK", f"expected MOCK integration before delete, got {got.get('type')!r}"

    apigw.delete_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")

    code, message = _error(
        lambda: apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Integration identifier specified", f"unexpected message {message!r}"

    # The method itself survives the integration's removal; only the integration is gone.
    method = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert method["httpMethod"] == "GET", f"expected the method to survive, got {method.get('httpMethod')!r}"
    assert "methodIntegration" not in method or method.get("methodIntegration") is None, (
        f"expected no methodIntegration after delete, got {method.get('methodIntegration')!r}"
    )

    # The identifier is reusable: the same resourceId/httpMethod can be re-wired afterward.
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    reattached = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert reattached["type"] == "MOCK", (
        f"expected the method to accept a fresh integration after delete, got {reattached.get('type')!r}"
    )


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
