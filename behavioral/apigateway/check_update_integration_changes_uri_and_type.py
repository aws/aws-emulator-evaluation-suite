"""update-integration-changes-uri-and-type."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-integration-changes-uri-and-type"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIntegration patches an HTTP integration's uri and httpMethod, visible via GetIntegration.
    The integration type is not patchable, so it must be unchanged by the update.
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
        uri="https://example.com/original-backend",
    )

    initial = apigw.get_integration(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert initial["type"] == "HTTP", f"expected type HTTP, got {initial.get('type')!r}"
    assert initial["uri"] == "https://example.com/original-backend", (
        f"expected uri 'https://example.com/original-backend', got {initial.get('uri')!r}"
    )
    assert initial["httpMethod"] == "GET", f"expected httpMethod GET, got {initial.get('httpMethod')!r}"

    apigw.update_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        patchOperations=[
            {"op": "replace", "path": "/uri", "value": "https://example.com/updated-backend"},
            {"op": "replace", "path": "/httpMethod", "value": "POST"},
        ],
    )

    updated = apigw.get_integration(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert updated["uri"] == "https://example.com/updated-backend", (
        f"expected uri 'https://example.com/updated-backend', got {updated.get('uri')!r}"
    )
    assert updated["httpMethod"] == "POST", f"expected httpMethod POST, got {updated.get('httpMethod')!r}"
    assert updated["type"] == "HTTP", (
        f"integration type must remain unchanged by UpdateIntegration, got {updated.get('type')!r}"
    )


def _create_api_with_resource(ctx: Any, apigw: Any) -> tuple[str, str]:
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]
    return api_id, resource_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
