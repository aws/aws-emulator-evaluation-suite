"""update-resource-rename-pathpart."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-resource-rename-pathpart"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Patching a resource's pathPart changes its path while resourceId/parentId stay stable."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"),
        tags={"sim2real": "update-resource-rename-pathpart"},
    )["id"]
    ctx.on_cleanup(lambda: _best_effort(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )

    created = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="orders")
    resource_id = created["id"]
    assert created["path"] == "/orders", f"expected /orders, got {created['path']!r}"
    assert created["parentId"] == root_id, f"expected parentId {root_id!r}, got {created['parentId']!r}"

    apigw.update_resource(
        restApiId=api_id, resourceId=resource_id,
        patchOperations=[{"op": "replace", "path": "/pathPart", "value": "items"}],
    )

    got = apigw.get_resource(restApiId=api_id, resourceId=resource_id)
    assert got["pathPart"] == "items", f"expected pathPart 'items', got {got['pathPart']!r}"
    assert got["path"] == "/items", f"expected path /items, got {got['path']!r}"
    assert got["id"] == resource_id, "resourceId must remain stable across the rename"
    assert got["parentId"] == root_id, "parentId must remain stable across the rename"


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
