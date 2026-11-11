"""create-resource-duplicate-pathpart-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resource-duplicate-pathpart-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResource rejects a second sibling resource with a pathPart that already
    exists under the same parent (a uniqueness/state-conflict boundary), and the same
    pathPart becomes creatable again once the conflicting sibling is removed."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "create-resource-duplicate-pathpart-conflict-rejected"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    first_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]

    code, message = _error(
        lambda: apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = "Another resource with the same parent already has this name: widgets"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The resource tree must still only contain the original "widgets" sibling.
    resources = apigw.get_resources(restApiId=api_id)["items"]
    # The root resource has no "pathPart" key, so use .get() to avoid a KeyError.
    widget_resources = [r for r in resources if r.get("pathPart") == "widgets"]
    assert widget_resources == [r for r in resources if r.get("id") == first_id] and len(
        widget_resources
    ) == 1, widget_resources

    # Restore: the conflict is state, not the input — removing the sibling that occupies
    # the pathPart must make the identical call succeed again.
    apigw.delete_resource(restApiId=api_id, resourceId=first_id)
    second_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]
    assert second_id != first_id, "expected a freshly minted resource id, not the deleted one"

    resources_after = apigw.get_resources(restApiId=api_id)["items"]
    widget_resources_after = [r for r in resources_after if r.get("pathPart") == "widgets"]
    assert widget_resources_after == [
        r for r in resources_after if r.get("id") == second_id
    ] and len(widget_resources_after) == 1, widget_resources_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
