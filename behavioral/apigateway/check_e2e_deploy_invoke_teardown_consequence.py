"""e2e-deploy-invoke-teardown-consequence."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-deploy-invoke-teardown-consequence"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Build+deploy a REST API with a real MOCK integration, invoke it end-to-end, tear it
    down, and confirm the API is actually gone (GetRestApi -> NotFoundException)."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-e2e-api-"),
        tags={"sim2real-check": CHECK},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_ignore_missing(apigw, api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="hello")
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
        responseTemplates={"application/json": '{"message": "hello-e2e"}'},
    )

    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = "prod"
    apigw.create_stage(
        restApiId=api_id, stageName=stage_name, deploymentId=deployment["id"]
    )

    # Observe the integration's canned response actually propagate through the deployed
    # method, end to end (MOCK integration -> integration response -> method response).
    invoke = apigw.test_invoke_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert invoke["status"] == 200, f"expected 200, got {invoke['status']}: {invoke.get('body')}"
    assert invoke["body"] == '{"message": "hello-e2e"}', (
        f"expected the configured integration response body, got {invoke['body']!r}"
    )

    # Tear the whole API down.
    apigw.delete_rest_api(restApiId=api_id)

    # Consequence: the API is really gone, not just "marked deleted" -- both a read and a
    # mutation against the dead id must fail with the specific not-found code.
    not_found = ("NotFoundException", f"Invalid API identifier specified {ctx.account}:{api_id}")
    read_err = _error(lambda: apigw.get_rest_api(restApiId=api_id))
    assert read_err == not_found, f"expected {not_found!r}, got {read_err!r}"

    mutate_err = _error(
        lambda: apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="post-delete")
    )
    assert mutate_err == not_found, (
        f"expected a mutation on the deleted api to fail with {not_found!r}, got {mutate_err!r}"
    )


def _delete_rest_api_ignore_missing(apigw, api_id: str) -> None:
    try:
        apigw.delete_rest_api(restApiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
