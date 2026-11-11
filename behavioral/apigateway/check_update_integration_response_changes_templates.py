"""update-integration-response-changes-templates."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-integration-response-changes-templates"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIntegrationResponse creates an integration response with a response
    mapping template; UpdateIntegrationResponse then patches that template value,
    and the change is reflected by GetIntegrationResponse.
    """
    apigw = ctx.client("apigateway")
    api_id, resource_id = _create_api_with_resource(ctx, apigw)

    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="HTTP",
        integrationHttpMethod="GET",
        uri="https://example.com/backend",
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"original": true}'},
    )

    initial = apigw.get_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    assert initial["responseTemplates"]["application/json"] == '{"original": true}', (
        f"expected the original template to persist, got {initial.get('responseTemplates')}"
    )

    apigw.update_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        patchOperations=[
            {
                "op": "replace",
                "path": "/responseTemplates/application~1json",
                "value": '{"updated": true}',
            }
        ],
    )

    updated = apigw.get_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    assert updated["responseTemplates"]["application/json"] == '{"updated": true}', (
        f"expected the patched template, got {updated.get('responseTemplates')}"
    )
    assert updated["statusCode"] == "200", (
        f"expected statusCode key to remain '200' after the template patch, got {updated.get('statusCode')!r}"
    )


def _create_api_with_resource(ctx: Any, apigw: Any) -> tuple[str, str]:
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]
    return api_id, resource_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
