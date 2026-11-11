"""test-invoke-method-executes-configured-integration."""
from __future__ import annotations

import json
import random
import string

from behavioral_harness import tags

CHECK = "test-invoke-method-executes-configured-integration"
GROUP = 'invoke'
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
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _scratch_resource(ctx, ag, api_id, path_part=None):
    """A fresh, uniquely named child resource off root (registered for teardown)."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part or f"r{_unique_token()}"
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id))
    return resource_id


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeMethod runs the configured MOCK integration's response template against the actual
    request: two different `name` query parameters produce two differently mapped bodies, so the
    response is not canned."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _scratch_resource(ctx, ag, api_id, "echo")

    ag.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
        requestParameters={"method.request.querystring.name": False},
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    ag.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={
            "application/json": '{"greeting": "hello $input.params(\'name\')"}'
        },
    )

    resp_alice = ag.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        pathWithQueryString="/echo?name=alice",
    )
    assert resp_alice["status"] == 200, f"expected status 200, got {resp_alice.get('status')!r}"
    body_alice = json.loads(resp_alice["body"])
    assert body_alice.get("greeting") == "hello alice", (
        f"expected the configured integration response template to reflect the real "
        f"query-string parameter, got {body_alice!r}"
    )

    resp_bob = ag.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        pathWithQueryString="/echo?name=bob",
    )
    body_bob = json.loads(resp_bob["body"])
    assert body_bob.get("greeting") == "hello bob", (
        f"expected a DIFFERENT input to produce a DIFFERENTLY-mapped output "
        f"(proving server-side template execution, not a cached/canned reply), got {body_bob!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
