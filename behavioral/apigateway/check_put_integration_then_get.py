"""put-integration-then-get."""
from __future__ import annotations

import random
import string

from behavioral_harness import tags

CHECK = "put-integration-then-get"
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
        tags={"sim2real-check": CHECK},
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
    """PutIntegration attaches a MOCK integration retrievable via GetIntegration.

    Round-trips every field the call was actually given, not just `type` — a target that
    stores `type` but drops `passthroughBehavior`/`requestTemplates` must not read as correct.
    """
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _scratch_resource(ctx, ag, api_id)
    ag.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )

    request_template = '{"statusCode": 200}'
    ag.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        passthroughBehavior="NEVER",
        requestTemplates={"application/json": request_template},
    )
    got = ag.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert got["type"] == "MOCK", f"expected MOCK, got {got['type']}"
    assert got.get("passthroughBehavior") == "NEVER", (
        f"expected passthroughBehavior NEVER, got {got.get('passthroughBehavior')}"
    )
    assert got.get("requestTemplates", {}).get("application/json") == request_template, (
        f"expected requestTemplates['application/json'] == {request_template!r}, "
        f"got {got.get('requestTemplates', {}).get('application/json')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
