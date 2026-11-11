"""e2e-full-api-lifecycle-deploy-invoke-teardown."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-full-api-lifecycle-deploy-invoke-teardown"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full create->resource->method->integration->deploy->stage->invoke flow returns the
    configured MOCK response, and after teardown the RestApi is genuinely gone (GetRestApi 404)."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        tags={"sim2real-check": CHECK},
    )
    api_id = api["id"]

    def _cleanup_api():
        try:
            apigw.delete_rest_api(restApiId=api_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_api)

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")
    resource_id = resource["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )
    apigw.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
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
        responseTemplates={"application/json": '{"message": "hello-mock"}'},
    )

    deployment = apigw.create_deployment(restApiId=api_id)
    deployment_id = deployment["id"]

    stage_name = "teststage"
    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
    )

    invoke = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
    )
    assert invoke["status"] == 200, f"expected 200, got {invoke['status']}: {invoke.get('body')}"
    assert invoke["body"] == '{"message": "hello-mock"}', (
        f"expected body '{{\"message\": \"hello-mock\"}}', got {invoke['body']!r}"
    )

    # Teardown: delete the stage then the RestApi, and confirm the API is genuinely gone.
    apigw.delete_stage(restApiId=api_id, stageName=stage_name)
    apigw.delete_rest_api(restApiId=api_id)

    gone_message = f"Invalid API identifier specified {ctx.account}:{api_id}"
    code, message = _error(lambda: apigw.get_rest_api(restApiId=api_id))
    assert code == "NotFoundException", f"expected NotFoundException after teardown, got {code}"
    assert message == gone_message, f"unexpected NotFoundException message {message!r}"

    # A mutation against the dead id must fail too, not just a read.
    mutate_code, mutate_message = _error(
        lambda: apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="post-teardown")
    )
    assert mutate_code == "NotFoundException", (
        f"expected NotFoundException creating a resource on a deleted RestApi, got {mutate_code}"
    )
    assert mutate_message == gone_message, (
        f"unexpected NotFoundException message {mutate_message!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
