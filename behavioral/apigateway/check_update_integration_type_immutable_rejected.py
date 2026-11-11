"""update-integration-type-immutable-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-integration-type-immutable-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIntegration rejects a patch of /type with BadRequestException; the type stays HTTP.
    An integration's type is fixed at PutIntegration; a /uri patch on it still succeeds.
    """
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]

    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="HTTP",
        integrationHttpMethod="GET",
        uri="https://example.com/backend",
    )

    # Positive control: UpdateIntegration itself works for a supported patch path, so the
    # rejection below is attributable to `/type` specifically and not to every call being refused.
    control = apigw.update_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        patchOperations=[{"op": "replace", "path": "/uri", "value": "https://example.com/updated-backend"}],
    )
    assert control["uri"] == "https://example.com/updated-backend", control.get("uri")

    err = _client_error(
        lambda: apigw.update_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            patchOperations=[{"op": "replace", "path": "/type", "value": "HTTP_PROXY"}],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid patch path /type", (
        f"expected the exact patch-path refusal message, got {err.get('Message')!r}"
    )

    # Confirm the rejected call had no side effect: type is still what PutIntegration set, and
    # the prior valid mutation from the positive control remains intact.
    unchanged = apigw.get_integration(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert unchanged["type"] == "HTTP", unchanged.get("type")
    assert unchanged["uri"] == "https://example.com/updated-backend", (
        "prior valid mutation must remain intact after the rejected patch"
    )


def _client_error(fn: Any) -> dict[str, Any]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected UpdateIntegration to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
