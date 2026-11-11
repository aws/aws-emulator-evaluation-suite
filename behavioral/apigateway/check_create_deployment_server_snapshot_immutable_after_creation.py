"""create-deployment-server-snapshot-immutable-after-creation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-deployment-server-snapshot-immutable-after-creation"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Deployment's apiSummary snapshot stays frozen even after later method/integration edits."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    deployment_id = apigw.create_deployment(restApiId=api_id, description="v1")["id"]

    # apiSummary is only populated when explicitly requested via embed=apisummary.
    snapshot_before = apigw.get_deployment(
        restApiId=api_id, deploymentId=deployment_id, embed=["apisummary"]
    ).get("apiSummary", {})
    methods_at_deploy = set(snapshot_before.get("/", {}).keys())
    assert methods_at_deploy == {"GET"}, f"expected deployment snapshot to record only GET, got {methods_at_deploy}"

    # Mutate the LIVE API after the deployment snapshot was already taken.
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="POST", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="POST", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    live_methods = set(apigw.get_resource(restApiId=api_id, resourceId=root_id)["resourceMethods"].keys())
    assert live_methods == {"GET", "POST"}, f"expected live resource to show both methods, got {live_methods}"

    snapshot_after = apigw.get_deployment(
        restApiId=api_id, deploymentId=deployment_id, embed=["apisummary"]
    ).get("apiSummary", {})
    methods_in_snapshot_after = set(snapshot_after.get("/", {}).keys())
    assert methods_in_snapshot_after == {"GET"}, (
        f"deployment snapshot mutated after creation: expected {{'GET'}}, got {methods_in_snapshot_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
