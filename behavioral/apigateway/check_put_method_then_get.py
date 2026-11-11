"""put-method-then-get."""
from __future__ import annotations

import random
import string

from behavioral_harness import tags

CHECK = "put-method-then-get"
GROUP = 'methods-integrations'
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
        tags={"sim2real": "put-method-then-get"},
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMethod persists authorizationType, httpMethod and the apiKeyRequired default, retrievable via GetMethod."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _scratch_resource(ctx, ag, api_id)

    ag.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    got = ag.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert got["httpMethod"] == "GET", f"expected httpMethod GET, got {got.get('httpMethod')!r}"
    assert got["authorizationType"] == "NONE", (
        f"expected authorizationType NONE, got {got.get('authorizationType')!r}"
    )
    assert got["apiKeyRequired"] is False, (
        f"expected apiKeyRequired to default False, got {got.get('apiKeyRequired')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
