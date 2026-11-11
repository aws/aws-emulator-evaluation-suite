"""update-integration-patch-uri."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-integration-patch-uri"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIntegration changes integration URI while preserving integration type."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    created = apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="HTTP",
        integrationHttpMethod="GET", uri="https://example.com/a",
    )
    assert created["type"] == "HTTP", f"expected type=HTTP after PutIntegration, got {created.get('type')}"
    assert created["uri"] == "https://example.com/a", (
        f"expected uri=https://example.com/a after PutIntegration, got {created.get('uri')}"
    )

    updated = apigw.update_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET",
        patchOperations=[{"op": "replace", "path": "/uri", "value": "https://example.com/b"}],
    )
    assert updated["uri"] == "https://example.com/b", (
        f"expected uri=https://example.com/b after UpdateIntegration, got {updated.get('uri')}"
    )
    assert updated["type"] == "HTTP", f"UpdateIntegration must not change integration type, got {updated.get('type')}"
    assert updated["httpMethod"] == "GET", (
        f"UpdateIntegration must preserve the backend integrationHttpMethod, got {updated.get('httpMethod')}"
    )

    fetched = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert fetched["uri"] == "https://example.com/b", (
        f"expected independent read to reflect patched uri, got {fetched.get('uri')}"
    )
    assert fetched["type"] == "HTTP", f"expected independent read to preserve type=HTTP, got {fetched.get('type')}"


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-bh-api-"),
        tags={"sim2real": "update-integration-patch-uri"},
    )
    api_id = resp["id"]
    root_id = resp["rootResourceId"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
