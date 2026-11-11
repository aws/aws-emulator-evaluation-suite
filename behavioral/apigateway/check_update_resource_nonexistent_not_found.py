"""update-resource-nonexistent-not-found."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-resource-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateResource after DeleteResource returns NotFoundException for the removed resource id,
    the identical call succeeds on the live resource beforehand, and the deleted id is confirmed
    gone by an independent read too."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-bhv-api-"),
        tags={"sim2real": "update-resource-nonexistent-not-found"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")
    resource_id = resource["id"]

    # Positive control: the identical UpdateResource call succeeds while the resource is live, so
    # the later failure is attributable to the delete rather than UpdateResource never working.
    updated = apigw.update_resource(
        restApiId=api_id,
        resourceId=resource_id,
        patchOperations=[{"op": "replace", "path": "/pathPart", "value": "gizmos"}],
    )
    assert updated["pathPart"] == "gizmos", f"positive control did not apply, got {updated['pathPart']!r}"
    confirmed = apigw.get_resource(restApiId=api_id, resourceId=resource_id)
    assert confirmed["pathPart"] == "gizmos", f"expected the positive control to be visible on read, got {confirmed['pathPart']!r}"

    apigw.delete_resource(restApiId=api_id, resourceId=resource_id)

    # Independent read: the resource is gone, not merely un-updatable.
    get_err = _client_error(lambda: apigw.get_resource(restApiId=api_id, resourceId=resource_id))
    assert get_err.get("Code") == "NotFoundException", (
        f"expected NotFoundException reading a deleted resource, got {get_err.get('Code')!r}"
    )
    assert get_err.get("Message") == "Invalid Resource identifier specified", (
        f"expected the exact NotFound message reading a deleted resource, got {get_err.get('Message')!r}"
    )

    err = _client_error(
        lambda: apigw.update_resource(
            restApiId=api_id,
            resourceId=resource_id,
            patchOperations=[{"op": "replace", "path": "/pathPart", "value": "gadgets"}],
        )
    )
    assert err.get("Code") == "NotFoundException", (
        f"expected NotFoundException on a deleted resource, got {err.get('Code')!r}"
    )
    assert err.get("Message") == "Invalid Resource identifier specified", (
        f"expected the exact NotFound message on a deleted resource, got {err.get('Message')!r}"
    )


def _client_error(fn: Any) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
