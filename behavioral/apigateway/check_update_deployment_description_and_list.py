"""update-deployment-description-and-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-deployment-description-and-list"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDeployment patches the description field of one deployment while
    GetDeployments continues to list every deployment for the API."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-upddeploy-"), tags={"sim2real": "true"}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    dep1 = apigw.create_deployment(restApiId=api_id, description="v1")["id"]
    dep2 = apigw.create_deployment(restApiId=api_id, description="v2")["id"]
    assert dep1 != dep2, f"expected two distinct deployment ids, got {dep1!r} twice"

    apigw.update_deployment(
        restApiId=api_id,
        deploymentId=dep1,
        patchOperations=[{"op": "replace", "path": "/description", "value": "v1-updated"}],
    )

    deployments = apigw.get_deployments(restApiId=api_id)["items"]
    by_id = {d["id"]: d for d in deployments}
    assert dep1 in by_id and dep2 in by_id, f"expected both deployments listed, got {list(by_id)}"
    assert by_id[dep1]["description"] == "v1-updated", (
        f"expected patched deployment {dep1} description 'v1-updated', got {by_id[dep1]!r}"
    )
    assert by_id[dep2]["description"] == "v2", (
        f"expected untouched deployment {dep2} description unchanged at 'v2', got {by_id[dep2]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
