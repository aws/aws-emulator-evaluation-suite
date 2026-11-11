"""delete-method-removes-integration."""
from __future__ import annotations

import random
import string
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-method-removes-integration"
GROUP = 'methods-integrations'
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
        tags={"sim2real": CHECK},
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteMethod removes the method's integration as well: an independent GetIntegration read
    404s afterward, and a fresh PutIntegration against the same (now dead) method is rejected
    rather than silently reviving it."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _scratch_resource(ctx, ag, api_id)
    ag.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    ag.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK"
    )

    ag.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")

    code, message = _error(
        lambda: ag.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Integration identifier specified", f"unexpected message: {message!r}"

    code, message = _error(
        lambda: ag.put_integration(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK"
        )
    )
    assert code == "NotFoundException", (
        f"expected a fresh PutIntegration against the deleted method to be rejected "
        f"NotFoundException, got {code}"
    )
    assert message == "Invalid Method identifier specified", f"unexpected message: {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
