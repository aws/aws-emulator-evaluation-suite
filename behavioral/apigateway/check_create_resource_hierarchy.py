"""create-resource-hierarchy."""
from __future__ import annotations

import random
import string

from behavioral_harness import tags

CHECK = "create-resource-hierarchy"
GROUP = 'resources'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResource under root builds the expected nested path, confirmed by an
    independent read at the destination rather than the mutating call's own echo."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, rest_api_id)
    part = f"widgets{_unique_token()}"

    child = ag.create_resource(restApiId=rest_api_id, parentId=root_id, pathPart=part)
    grandchild = ag.create_resource(restApiId=rest_api_id, parentId=child["id"], pathPart="{id}")

    # terminal read: GetResource, an independent operation from the CreateResource
    # calls above, so the assertion cannot be satisfied by an echo of the request.
    child_read = ag.get_resource(restApiId=rest_api_id, resourceId=child["id"])
    assert child_read["path"] == f"/{part}", f"unexpected path {child_read['path']}"
    assert child_read["parentId"] == root_id, (
        f"expected child parentId {root_id}, got {child_read['parentId']}"
    )

    grandchild_read = ag.get_resource(restApiId=rest_api_id, resourceId=grandchild["id"])
    assert grandchild_read["path"] == f"/{part}/{{id}}", (
        f"unexpected nested path {grandchild_read['path']}"
    )
    assert grandchild_read["parentId"] == child["id"], (
        f"expected grandchild parentId {child['id']}, got {grandchild_read['parentId']}"
    )

    # the hierarchy must also be visible in the collection view, not just per-id
    listed = {item["id"]: item["path"] for item in ag.get_resources(restApiId=rest_api_id)["items"]}
    assert listed.get(child["id"]) == f"/{part}", (
        f"child not visible with expected path in GetResources: {listed}"
    )
    assert listed.get(grandchild["id"]) == f"/{part}/{{id}}", (
        f"grandchild not visible with expected path in GetResources: {listed}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
