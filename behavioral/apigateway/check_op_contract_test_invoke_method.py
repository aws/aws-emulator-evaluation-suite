"""op-contract-testInvokeMethod."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-testInvokeMethod"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeMethod drives a real MOCK integration end to end and returns its rendered response body."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": "op-contract-testInvokeMethod"}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="echo")["id"]

    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "hello-mock"}'},
    )

    result = apigw.test_invoke_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert result["status"] == 200, f"expected mock backend to return 200, got {result['status']}"
    body = json.loads(result["body"])
    assert body == {"message": "hello-mock"}, f"expected the mock response template body, got {body!r}"

    code, message = _error(
        lambda: apigw.test_invoke_method(restApiId=api_id, resourceId="nonexistent-resource-id", httpMethod="GET")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Resource identifier specified", message


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
