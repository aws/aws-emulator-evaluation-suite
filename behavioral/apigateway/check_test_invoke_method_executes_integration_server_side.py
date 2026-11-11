"""test-invoke-method-executes-integration-server-side."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-invoke-method-executes-integration-server-side"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeMethod maps two different query strings through the MOCK integration's response
    template into two different bodies, and needs no deployment or stage, nor creates one."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-invoke-api-"),
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="echo")["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
        requestParameters={"method.request.querystring.name": False},
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "hello $input.params(\'name\')"}'},
    )

    # No CreateDeployment / CreateStage call has been made -- prove the emulator executes the
    # method server-side purely from stored resource/method/integration config.
    deployments_before = apigw.get_deployments(restApiId=api_id).get("items", [])
    assert deployments_before == [], f"no deployments should exist before TestInvokeMethod, got {deployments_before!r}"

    resp_alice = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        pathWithQueryString="/echo?name=alice",
    )
    assert resp_alice["status"] == 200, f"expected status 200, got {resp_alice!r}"
    body_alice = json.loads(resp_alice["body"])
    assert body_alice.get("message") == "hello alice", (
        f"expected the integration response mapping template to be evaluated against the real "
        f"querystring parameter server-side, got {body_alice!r}"
    )
    latency = resp_alice.get("latency")
    assert isinstance(latency, int) and 0 <= latency < 60_000, (
        f"expected a plausible non-negative server-captured latency (ms), got {latency!r}"
    )
    assert resp_alice.get("log"), f"TestInvokeMethod should return a non-empty execution log, got {resp_alice.get('log')!r}"

    resp_bob = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        pathWithQueryString="/echo?name=bob",
    )
    assert resp_bob["status"] == 200, f"expected status 200, got {resp_bob!r}"
    body_bob = json.loads(resp_bob["body"])
    assert body_bob.get("message") == "hello bob", (
        f"a DIFFERENT request must produce a DIFFERENTLY-mapped response (proving the template is "
        f"evaluated server-side per request, not replayed from a cached/canned literal), got {body_bob!r}"
    )

    deployments_after = apigw.get_deployments(restApiId=api_id).get("items", [])
    assert deployments_after == [], f"TestInvokeMethod must not create a deployment as a side effect, got {deployments_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
