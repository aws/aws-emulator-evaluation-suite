"""op-contract-delete-method-response."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-delete-method-response"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteMethodResponse removes exactly the targeted statusCode entry (a subsequent
    GetMethodResponse for it is NotFoundException); a statusCode that was never defined on
    an existing method is also rejected with NotFoundException."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    created_status = apigw.get_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )["statusCode"]
    assert created_status == "200", f"expected positive control statusCode 200, got {created_status}"

    apigw.delete_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    err = _client_error(
        lambda: apigw.get_method_response(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
        )
    )
    assert err.get("Code") == "NotFoundException", f"expected 200 methodResponse gone, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Response status code specified", (
        f"expected the exact NotFound message from GetMethodResponse, got {err.get('Message')!r}"
    )

    # error boundary: a statusCode that was never defined on this (still-existing) method -> NotFoundException
    err2 = _client_error(
        lambda: apigw.delete_method_response(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="500"
        )
    )
    assert err2.get("Code") == "NotFoundException", f"expected NotFoundException for undefined statusCode, got {err2.get('Code')!r}"
    assert err2.get("Message") == "Invalid Response status code specified", (
        f"expected the exact NotFound message from DeleteMethodResponse, got {err2.get('Message')!r}"
    )
    # the method itself is untouched by the failed call
    method_after = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")["httpMethod"]
    assert method_after == "GET", f"expected method untouched by failed delete, got {method_after}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
