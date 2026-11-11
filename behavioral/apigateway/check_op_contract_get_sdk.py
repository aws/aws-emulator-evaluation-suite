"""op-contract-getSdk."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-getSdk"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSdk generates a real downloadable SDK zip archive for a deployed stage;
    an unsupported sdkType is rejected."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    sdk = apigw.get_sdk(restApiId=api_id, stageName=stage_name, sdkType="javascript")
    body = sdk["body"].read()
    assert len(body) > 100, f"expected a non-trivial generated SDK bundle, got {len(body)} bytes"
    assert body[:2] == b"PK", f"generated SDK is delivered as a ZIP archive, got header {body[:4]!r}"

    code, message = _error(
        lambda: apigw.get_sdk(restApiId=api_id, stageName=stage_name, sdkType="not-a-real-sdk-type")
    )
    assert code == "BadRequestException", f"expected BadRequestException for an unsupported sdkType, got {code}"
    assert message == "No SDK generator for type 'not-a-real-sdk-type'", f"unexpected message: {message!r}"


def _error(fn) -> Any:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
