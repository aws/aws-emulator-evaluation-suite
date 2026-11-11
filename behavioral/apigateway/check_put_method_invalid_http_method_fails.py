"""put-method-invalid-http-method-fails."""
from __future__ import annotations

import random
import string
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-method-invalid-http-method-fails"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")

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

def _scratch_resource(ctx, ag, api_id):
    """A fresh, uniquely named child resource off root (registered for teardown)."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=f"r{_unique_token()}"
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id))
    return resource_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMethod with an unsupported httpMethod verb must fail (overly-permissive check)."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _scratch_resource(ctx, ag, api_id)

    code, message = _error(
        lambda: ag.put_method(
            restApiId=api_id, resourceId=root_id, httpMethod="FETCH", authorizationType="NONE"
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        "Invalid HttpMethod specified. Valid options are GET,PUT,POST,DELETE,PATCH,OPTIONS,HEAD,ANY"
    ), f"unexpected message: {message!r}"

    # Effect absent: the resource carries no method under the rejected verb.
    resource = ag.get_resource(restApiId=api_id, resourceId=root_id, embed=["methods"])
    assert "FETCH" not in resource.get("resourceMethods", {}), (
        "a method was created despite the rejected PutMethod"
    )

    # Positive control: a valid httpMethod on the same resource still succeeds, proving the
    # rejection is about the httpMethod value, not the operation itself.
    control = ag.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    assert control["httpMethod"] == "GET", f"positive control did not create a GET method: {control}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
