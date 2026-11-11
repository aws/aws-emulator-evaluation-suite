"""resource-pathpart-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-pathpart-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource that would collide with an existing sibling path is rejected with ConflictException,
    leaving the resource's pathPart unchanged; once the sibling is removed, the identical rename succeeds —
    proving the sibling's occupancy, not UpdateResource itself, was the cause."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-rescollide-")
    rest_api_id = apigw.create_rest_api(name=name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]

    resource_foo = apigw.create_resource(restApiId=rest_api_id, parentId=root_id, pathPart="foo")
    resource_foo_id = resource_foo["id"]
    resource_baz = apigw.create_resource(restApiId=rest_api_id, parentId=root_id, pathPart="baz")
    resource_baz_id = resource_baz["id"]
    assert resource_baz["path"] == "/baz", f"expected path /baz, got {resource_baz['path']!r}"

    # Positive control: renaming to a free pathPart succeeds — proves UpdateResource works at all.
    apigw.update_resource(
        restApiId=rest_api_id,
        resourceId=resource_foo_id,
        patchOperations=[{"op": "replace", "path": "/pathPart", "value": "qux"}],
    )
    control = apigw.get_resource(restApiId=rest_api_id, resourceId=resource_foo_id)
    assert control["pathPart"] == "qux", f"expected pathPart 'qux' after rename, got {control['pathPart']!r}"
    assert control["path"] == "/qux", f"expected path /qux after rename, got {control['path']!r}"

    # Break exactly one precondition: rename /qux (was /foo) to a pathPart already used by sibling /baz.
    code, message = _error(
        lambda: apigw.update_resource(
            restApiId=rest_api_id,
            resourceId=resource_foo_id,
            patchOperations=[{"op": "replace", "path": "/pathPart", "value": "baz"}],
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == "Another resource with the same parent already has this name: baz", (
        f"unexpected message: {message!r}"
    )

    # The forbidden effect did not happen: the resource is still /qux, not /baz.
    unaffected = apigw.get_resource(restApiId=rest_api_id, resourceId=resource_foo_id)
    assert unaffected["pathPart"] == "qux", f"pathPart must remain 'qux' after rejected update, got {unaffected['pathPart']!r}"
    assert unaffected["path"] == "/qux", f"path must remain /qux after rejected update, got {unaffected['path']!r}"

    # Restore: remove the conflicting sibling so "baz" is free again.
    apigw.delete_resource(restApiId=rest_api_id, resourceId=resource_baz_id)

    # The identical rename now succeeds.
    apigw.update_resource(
        restApiId=rest_api_id,
        resourceId=resource_foo_id,
        patchOperations=[{"op": "replace", "path": "/pathPart", "value": "baz"}],
    )
    restored = apigw.get_resource(restApiId=rest_api_id, resourceId=resource_foo_id)
    assert restored["pathPart"] == "baz", f"expected pathPart 'baz' once sibling removed, got {restored['pathPart']!r}"
    assert restored["path"] == "/baz", f"expected path /baz once sibling removed, got {restored['path']!r}"


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
