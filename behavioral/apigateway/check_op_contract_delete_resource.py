"""op-contract-deleteResource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deleteResource"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteResource on a parent cascades to remove its child resource too; deleting a
    resourceId that does not exist -- or one already deleted -- is rejected with
    NotFoundException."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)

    parent = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="parent")
    parent_id = parent["id"]
    child = apigw.create_resource(restApiId=api_id, parentId=parent_id, pathPart="child")
    child_id = child["id"]
    assert child["path"] == "/parent/child", f"expected nested path /parent/child, got {child['path']}"

    apigw.delete_resource(restApiId=api_id, resourceId=parent_id)

    err = _client_error(lambda: apigw.get_resource(restApiId=api_id, resourceId=parent_id))
    assert err.get("Code") == "NotFoundException", f"parent resource still present after delete, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Resource identifier specified", (
        f"expected the exact NotFound message for the deleted parent, got {err.get('Message')!r}"
    )

    err = _client_error(lambda: apigw.get_resource(restApiId=api_id, resourceId=child_id))
    assert err.get("Code") == "NotFoundException", f"child resource survived cascading delete, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Resource identifier specified", (
        f"expected the exact NotFound message for the cascaded child, got {err.get('Message')!r}"
    )

    err = _client_error(lambda: apigw.delete_resource(restApiId=api_id, resourceId=parent_id))
    assert err.get("Code") == "NotFoundException", f"double-delete of the already-deleted parent should be rejected, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Resource identifier specified", (
        f"expected the exact NotFound message from the double delete, got {err.get('Message')!r}"
    )

    err = _client_error(
        lambda: apigw.delete_resource(restApiId=api_id, resourceId="zzzznotarealresource")
    )
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException for bogus resourceId, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Resource identifier specified", (
        f"expected the exact NotFound message for a bogus resourceId, got {err.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real": "op-contract-deleteResource"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
