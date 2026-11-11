"""get-stages-lists-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-stages-lists-created"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stage created via CreateStage is enumerable via GetStages with its deploymentId/variables intact."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-stages-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]

    apigw.create_stage(
        restApiId=api_id, stageName="dev", deploymentId=deployment_id, variables={"env": "dev"}
    )

    stages = apigw.get_stages(restApiId=api_id)["item"]
    matches = [s for s in stages if s["stageName"] == "dev"]
    assert len(matches) == 1, f"expected exactly one 'dev' stage in {stages}"
    assert matches[0]["deploymentId"] == deployment_id, (
        f"expected deploymentId {deployment_id}, got {matches[0]['deploymentId']}"
    )
    assert matches[0]["variables"] == {"env": "dev"}, (
        f"expected variables {{'env': 'dev'}}, got {matches[0]['variables']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
