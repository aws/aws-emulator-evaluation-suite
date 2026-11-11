"""update-resource-pathpart-preserves-children."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-resource-pathpart-preserves-children"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource relocates a resource in the tree while child resources/methods stay attached."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-resource-")
    rest_api_id = apigw.create_rest_api(name=name)["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]

    resource_a = apigw.create_resource(restApiId=rest_api_id, parentId=root_id, pathPart="foo")
    resource_a_id = resource_a["id"]
    assert resource_a["path"] == "/foo", f"expected path /foo, got {resource_a['path']!r}"

    resource_b = apigw.create_resource(restApiId=rest_api_id, parentId=resource_a_id, pathPart="bar")
    resource_b_id = resource_b["id"]
    assert resource_b["path"] == "/foo/bar", f"expected path /foo/bar, got {resource_b['path']!r}"

    apigw.put_method(restApiId=rest_api_id, resourceId=resource_b_id, httpMethod="GET", authorizationType="NONE")

    apigw.update_resource(
        restApiId=rest_api_id,
        resourceId=resource_a_id,
        patchOperations=[{"op": "replace", "path": "/pathPart", "value": "baz"}],
    )

    after_a = apigw.get_resource(restApiId=rest_api_id, resourceId=resource_a_id)
    assert after_a["id"] == resource_a_id, "the resource id must be preserved across a pathPart rename"
    assert after_a["pathPart"] == "baz", f"expected pathPart baz, got {after_a['pathPart']!r}"
    assert after_a["path"] == "/baz", f"expected path /baz, got {after_a['path']!r}"

    after_b = apigw.get_resource(restApiId=rest_api_id, resourceId=resource_b_id)
    assert after_b["id"] == resource_b_id, "the child resource id must be preserved"
    assert after_b["parentId"] == resource_a_id, (
        f"expected parentId {resource_a_id!r} (unchanged), got {after_b['parentId']!r}"
    )
    assert after_b["path"] == "/baz/bar", "the child path must relocate along with its renamed parent"
    assert "GET" in after_b["resourceMethods"], "the child's method must remain attached"

    method_after = apigw.get_method(restApiId=rest_api_id, resourceId=resource_b_id, httpMethod="GET")
    assert method_after["httpMethod"] == "GET", "the method must remain addressable via the (unchanged) resourceId"


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
