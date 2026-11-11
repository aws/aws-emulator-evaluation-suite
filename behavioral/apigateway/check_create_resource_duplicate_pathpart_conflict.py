"""create-resource-duplicate-pathpart-conflict."""
from __future__ import annotations

import random
import string
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resource-duplicate-pathpart-conflict"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating two resources with the same pathPart under one parent must conflict (overly-permissive check)."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, rest_api_id)
    part = f"items{_unique_token()}"

    # Positive control: the first create_resource succeeds cleanly.
    created = ag.create_resource(restApiId=rest_api_id, parentId=root_id, pathPart=part)

    # Break: the identical call, reusing the now-taken pathPart under the same parent, must conflict.
    code, message = _error(
        lambda: ag.create_resource(restApiId=rest_api_id, parentId=root_id, pathPart=part)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = f"Another resource with the same parent already has this name: {part}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: an independent read shows no second sibling was created, and the
    # original resource's id is untouched by the rejected duplicate.
    matching = [
        r for r in ag.get_resources(restApiId=rest_api_id)["items"]
        if r.get("pathPart") == part
    ]
    assert len(matching) == 1, (
        f"expected exactly one resource with pathPart {part!r} after the rejected "
        f"duplicate, found {len(matching)}"
    )
    assert matching[0]["id"] == created["id"], (
        f"rejected duplicate create_resource must not alter the existing resource: "
        f"expected id {created['id']!r}, got {matching[0]['id']!r}"
    )

    # Restore: freeing the pathPart lets the identical call succeed, proving the conflict
    # was about the parent+pathPart collision and not some other, permanent defect.
    ag.delete_resource(restApiId=rest_api_id, resourceId=created["id"])
    recreated = ag.create_resource(restApiId=rest_api_id, parentId=root_id, pathPart=part)
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=rest_api_id, resourceId=recreated["id"]))

    # Terminal read: independent read at the destination confirms the restored resource is live.
    restored = ag.get_resource(restApiId=rest_api_id, resourceId=recreated["id"])
    assert restored["pathPart"] == part, (
        f"expected the recreated resource to carry pathPart {part!r}, got {restored.get('pathPart')!r}"
    )
    assert restored["path"] == f"/{part}", (
        f"expected the recreated resource's path to be /{part}, got {restored.get('path')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
