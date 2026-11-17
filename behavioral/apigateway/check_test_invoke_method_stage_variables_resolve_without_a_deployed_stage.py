"""test-invoke-method-stage-variables-resolve-without-a-deployed-stage."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-invoke-method-stage-variables-resolve-without-a-deployed-stage"
GROUP = "server-side"
SERVICES = ["apigateway"]

_THROTTLED = "TooManyRequestsException"


def _delete_rest_api_quota_aware(apigw, api_id, *, budget_s: float = 320.0) -> None:
    """DeleteRestApi is quota'd to one call every 30s per account; retry the throttle."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != _THROTTLED or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def _root_id(apigw, api_id):
    for item in apigw.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"root ('/') resource not found on restApiId={api_id!r}")


def _backend_route(apigw, api_id, parent_id, path_part, body_text):
    resource_id = apigw.create_resource(restApiId=api_id, parentId=parent_id, pathPart=path_part)["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": body_text},
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeMethod resolves ${stageVariables.*} in an HTTP integration's URI from the
    stageVariables it is called with, even for a method whose API has never been deployed."""
    apigw = ctx.client("apigateway")

    # The backend: a deployed, separate REST API with two routes answering distinct bodies.
    backend_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-tivbackend-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_quota_aware(apigw, backend_id))
    backend_root = _root_id(apigw, backend_id)
    _backend_route(apigw, backend_id, backend_root, "alpha", '{"route": "alpha"}')
    _backend_route(apigw, backend_id, backend_root, "beta", '{"route": "beta"}')
    apigw.create_deployment(restApiId=backend_id, stageName="live")
    backend_url = ctx.rest_api_url(backend_id, "live")

    # The subject: a method whose integration URI names a stage variable, on an API that is
    # never deployed -- TestInvokeMethod must still resolve it from its own stageVariables arg.
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-tiv-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_quota_aware(apigw, api_id))
    root_id = _root_id(apigw, api_id)
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="route")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="HTTP",
        integrationHttpMethod="GET", uri=f"{backend_url}/${{stageVariables.target}}",
        passthroughBehavior="WHEN_NO_MATCH",
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200", selectionPattern="",
    )

    alpha = apigw.test_invoke_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        stageVariables={"target": "alpha"},
    )
    assert alpha["status"] == 200, f"expected status 200 for target=alpha, got {alpha['status']} (log={alpha.get('log', '')[:300]!r})"
    assert alpha["body"] == '{"route": "alpha"}', f"expected the alpha route's body, got {alpha['body']!r}"

    beta = apigw.test_invoke_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        stageVariables={"target": "beta"},
    )
    assert beta["status"] == 200, f"expected status 200 for target=beta, got {beta['status']} (log={beta.get('log', '')[:300]!r})"
    assert beta["body"] == '{"route": "beta"}', f"expected the beta route's body, got {beta['body']!r}"

    deployments = apigw.get_deployments(restApiId=api_id)["items"]
    assert deployments == [], (
        f"expected no deployment to exist on the subject API -- TestInvokeMethod must not need "
        f"one -- got {deployments!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
