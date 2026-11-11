"""update-resource-patch-pathpart."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-resource-patch-pathpart"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource changes pathPart while preserving parentId, reflected in GetResource."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)

    created = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="orig-part")
    resource_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_resource(restApiId=api_id, resourceId=resource_id))
    assert created["parentId"] == root_id, f"expected parentId {root_id!r}, got {created['parentId']!r}"
    assert created["path"] == "/orig-part", f"expected path '/orig-part', got {created['path']!r}"

    updated = apigw.update_resource(
        restApiId=api_id,
        resourceId=resource_id,
        patchOperations=[{"op": "replace", "path": "/pathPart", "value": "renamed-part"}],
    )
    assert updated["pathPart"] == "renamed-part", (
        f"expected pathPart 'renamed-part', got {updated['pathPart']!r}"
    )
    assert updated["parentId"] == root_id, "UpdateResource must preserve parentId"
    assert updated["path"] == "/renamed-part", f"expected path '/renamed-part', got {updated['path']!r}"

    fetched = apigw.get_resource(restApiId=api_id, resourceId=resource_id)
    assert fetched["id"] == resource_id, "resourceId must remain stable across a pathPart rename"
    assert fetched["pathPart"] == "renamed-part", (
        f"expected pathPart 'renamed-part' on independent read, got {fetched['pathPart']!r}"
    )
    assert fetched["parentId"] == root_id, (
        f"expected parentId {root_id!r} on independent read, got {fetched['parentId']!r}"
    )
    assert fetched["path"] == "/renamed-part", (
        f"expected path '/renamed-part' on independent read, got {fetched['path']!r}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-bh-api-"),
        tags={"sim2real": "update-resource-patch-pathpart"},
    )
    api_id = resp["id"]
    root_id = resp["rootResourceId"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
