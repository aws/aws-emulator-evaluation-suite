"""get-resource-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resource-nonexistent-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResource with a bogus resourceId must fail with NotFoundException, while GetResource
    on a real resourceId on the same API keeps succeeding (overly-permissive check) — the positive
    control rules out a target that rejects every GetResource, not just the missing one."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, rest_api_id)
    real_resource_id = ag.create_resource(
        restApiId=rest_api_id, parentId=root_id, pathPart="widgets"
    )["id"]

    positive = ag.get_resource(restApiId=rest_api_id, resourceId=real_resource_id)
    assert positive["id"] == real_resource_id, (
        f"expected the positive control to return the real resource {real_resource_id!r}, "
        f"got {positive.get('id')!r}"
    )

    code, message = _error(
        lambda: ag.get_resource(restApiId=rest_api_id, resourceId="bogusid123")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Resource identifier specified", f"unexpected message: {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
