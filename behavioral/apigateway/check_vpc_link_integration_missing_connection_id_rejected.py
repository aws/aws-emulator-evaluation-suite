"""vpc-link-integration-missing-connection-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "vpc-link-integration-missing-connection-id-rejected"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIntegration rejects an HTTP_PROXY integration declared connectionType=VPC_LINK without
    a connectionId, and leaves no partial integration behind on the method."""
    apigw = ctx.client("apigateway")
    rest_api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-vpclink-neg-api-")
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(
        restApiId=rest_api_id, parentId=root_id, pathPart="missing-link"
    )["id"]
    apigw.put_method(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )

    err = _client_error(
        lambda: apigw.put_integration(
            restApiId=rest_api_id,
            resourceId=resource_id,
            httpMethod="GET",
            type="HTTP_PROXY",
            integrationHttpMethod="GET",
            uri="http://example.com/",
            connectionType="VPC_LINK",
        )
    )
    expected = (
        "BadRequestException",
        "ConnectionId should be set to the vpcLinkId or stage variable on connection type VPC_LINK",
    )
    assert (err.get("Code"), err.get("Message")) == expected, f"expected {expected!r}, got {err!r}"

    err = _client_error(
        lambda: apigw.get_integration(
            restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
        )
    )
    expected = ("NotFoundException", "Invalid Integration identifier specified")
    assert (err.get("Code"), err.get("Message")) == expected, (
        f"a rejected PutIntegration must not create an integration, got {err!r}"
    )

    # Positive control: a MOCK integration on the same method still succeeds normally.
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    integration = apigw.get_integration(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
    )
    assert integration["type"] == "MOCK", f"expected MOCK integration, got {integration['type']}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
