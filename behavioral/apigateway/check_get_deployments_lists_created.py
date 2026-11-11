"""get-deployments-lists-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-deployments-lists-created"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deployments created via CreateDeployment are enumerable via GetDeployments."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-deploy-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": ""},
    )

    dep1 = apigw.create_deployment(restApiId=api_id, stageName="prod", description="sim2real deployment one")
    dep2 = apigw.create_deployment(restApiId=api_id, stageName="prod", description="sim2real deployment two")
    assert dep1["id"] != dep2["id"], f"two CreateDeployment calls returned the same id {dep1['id']!r}"

    stage = apigw.get_stage(restApiId=api_id, stageName="prod")
    assert stage["deploymentId"] == dep2["id"], "redeploying the stage should point it at the newest deployment"

    listed = {d["id"]: d for d in apigw.get_deployments(restApiId=api_id)["items"]}
    assert len(listed) == 2, f"expected exactly the 2 deployments this check created, got {sorted(listed)}"
    assert dep1["id"] in listed, listed.keys()
    assert dep2["id"] in listed, listed.keys()
    assert listed[dep1["id"]]["description"] == "sim2real deployment one", (
        f"expected 'sim2real deployment one', got {listed[dep1['id']]['description']!r}"
    )
    assert listed[dep2["id"]]["description"] == "sim2real deployment two", (
        f"expected 'sim2real deployment two', got {listed[dep2['id']]['description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
