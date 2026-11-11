"""e2e-full-api-lifecycle-through-invoke."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-full-api-lifecycle-through-invoke"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full REST API lifecycle: create -> resource -> method -> mock integration ->
    deploy -> stage -> TestInvokeMethod returns the configured mock response, and
    DeleteRestApi makes the API 404 to GetRestApi afterward."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-lifecycle-"),
        tags={"sim2real": "e2e-full-api-lifecycle-through-invoke"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _safe_delete_rest_api(apigw, api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")
    resource_id = resource["id"]

    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": json.dumps({"message": "hello-mock"})},
    )

    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = "prod"
    apigw.create_stage(
        restApiId=api_id, stageName=stage_name, deploymentId=deployment["id"]
    )

    result = apigw.test_invoke_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET"
    )
    assert result["status"] == 200, f"expected 200 from mock integration, got {result['status']}"
    body = json.loads(result["body"])
    assert body == {"message": "hello-mock"}, (
        f"expected mock response body {{'message': 'hello-mock'}}, got {body!r}"
    )

    apigw.delete_rest_api(restApiId=api_id)
    err = _error(lambda: apigw.get_rest_api(restApiId=api_id))
    expected = ("NotFoundException", f"Invalid API identifier specified {ctx.account}:{api_id}")
    assert err == expected, f"expected {expected!r} after delete, got {err!r}"


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_rest_api(apigw, api_id: str) -> None:
    try:
        apigw.delete_rest_api(restApiId=api_id)
    except apigw.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
