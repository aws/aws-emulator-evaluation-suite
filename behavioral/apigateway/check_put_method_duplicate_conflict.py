"""put-method-duplicate-conflict."""
from __future__ import annotations

import random
import string
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-method-duplicate-conflict"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")

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
        tags={"sim2real": "put-method-duplicate-conflict"},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _scratch_resource(ctx, ag, api_id):
    """A fresh, uniquely named child resource off root (registered for teardown)."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=f"r{_unique_token()}"
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id))
    return resource_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second PutMethod for an existing (resource, httpMethod) pair fails with ConflictException
    and its exact message, and leaves the existing method and integration unchanged:
    PutMethod is not an upsert."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _scratch_resource(ctx, ag, api_id)
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK"
    )

    code, message = _error(
        lambda: ag.put_method(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == "Method already exists for this resource", f"unexpected message: {message!r}"

    # The rejected duplicate must not have touched the existing method or its
    # integration -- prove it with an independent read, not by trusting the
    # error response.
    got = ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert got["authorizationType"] == "NONE", f"method mutated by rejected duplicate: {got}"
    integ = ag.get_integration(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert integ["type"] == "MOCK", f"integration mutated by rejected duplicate: {integ}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
