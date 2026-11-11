"""update-resource-not-found-error-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-resource-not-found-error-contract"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateResource on a resource removed out-of-band returns NotFoundException, and the
    rejected call does not resurrect the resource."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-restapi-"), tags={"sim2real": CHECK}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    child = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")
    child_id = child["id"]

    # Positive control: the same call shape, against the live resource, succeeds -- so the
    # rejection below is attributable to the resource being gone, not to anything else about
    # the request.
    patched = apigw.update_resource(
        restApiId=api_id,
        resourceId=child_id,
        patchOperations=[{"op": "replace", "path": "/pathPart", "value": "gadgets"}],
    )
    assert patched["pathPart"] == "gadgets", (
        f"positive control did not rename pathPart, got {patched.get('pathPart')!r}"
    )

    apigw.delete_resource(restApiId=api_id, resourceId=child_id)

    err = _client_error(
        lambda: apigw.update_resource(
            restApiId=api_id,
            resourceId=child_id,
            patchOperations=[{"op": "replace", "path": "/pathPart", "value": "widgets"}],
        )
    )
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Resource identifier specified", (
        f"expected the exact NotFound message, got {err.get('Message')!r}"
    )

    # the rejected update did not resurrect the resource
    err2 = _client_error(lambda: apigw.get_resource(restApiId=api_id, resourceId=child_id))
    assert err2.get("Code") == "NotFoundException", (
        f"a rejected UpdateResource on a deleted id left the resource visible via GetResource: "
        f"{err2.get('Code')!r}"
    )
    assert err2.get("Message") == "Invalid Resource identifier specified", (
        f"expected the exact NotFound message from GetResource, got {err2.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
