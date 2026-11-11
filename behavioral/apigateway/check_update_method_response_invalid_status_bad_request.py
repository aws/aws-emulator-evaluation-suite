"""update-method-response-invalid-status-bad-request."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-method-response-invalid-status-bad-request"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMethodResponse rejects a /statusCode patch with BadRequestException, leaving it intact.
    A valid patch succeeds first; after deletion, reads and updates fail with NotFoundException."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"), tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    # Positive control: a valid patch on the same method response succeeds.
    apigw.update_method_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        patchOperations=[{"op": "add", "path": "/responseModels/application~1json", "value": "Empty"}],
    )
    control = apigw.get_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    assert control.get("responseModels", {}).get("application/json") == "Empty", (
        f"positive control patch did not take effect: {control!r}"
    )

    err = _client_error(
        lambda: apigw.update_method_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            statusCode="200",
            patchOperations=[{"op": "replace", "path": "/statusCode", "value": "not-a-status"}],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid patch path /statusCode", (
        f"expected the exact patch-path refusal message, got {err.get('Message')!r}"
    )

    got = apigw.get_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    assert got["statusCode"] == "200"
    assert got.get("responseModels", {}).get("application/json") == "Empty", (
        f"the rejected patch must not have reverted the earlier successful patch: {got!r}"
    )

    apigw.delete_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    err = _client_error(
        lambda: apigw.get_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    )
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Response status code specified", (
        f"expected the exact NotFound message reading the deleted method response, got {err.get('Message')!r}"
    )

    mutate_err = _client_error(
        lambda: apigw.update_method_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            statusCode="200",
            patchOperations=[{"op": "add", "path": "/responseModels/application~1json", "value": "Empty"}],
        )
    )
    assert mutate_err.get("Code") == "NotFoundException", (
        f"expected NotFoundException, got {mutate_err.get('Code')!r}"
    )
    assert mutate_err.get("Message") == "Invalid Response status code specified", (
        f"expected the exact NotFound message updating the deleted method response, "
        f"got {mutate_err.get('Message')!r}"
    )

    # The status code is reusable after deletion.
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    recreated = apigw.get_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    assert recreated["statusCode"] == "200"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
