"""apigw-invoke-mock-integration."""
from __future__ import annotations

import json
import random
import string

from behavioral_harness import tags

CHECK = "apigw-invoke-mock-integration"
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeMethod on a GET method with a MOCK integration returns 200 with the static body its
    integration response template renders, without a deployed stage."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _scratch_resource(ctx, ag, api_id)

    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
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
        responseTemplates={"application/json": '{"message": "hello-from-mock"}'},
    )

    resp = ag.test_invoke_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET"
    )
    assert resp["status"] == 200, f"expected status 200, got {resp['status']}: {resp.get('body')}"
    body = json.loads(resp["body"])
    assert body == {"message": "hello-from-mock"}, (
        f"expected the integration response template's exact rendered body, got {body!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
