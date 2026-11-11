"""deployment-description-empty-string-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deployment-description-empty-string-preserved"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeployment with an explicit '' description returns it as absent on both the create
    response and GetDeployment; a non-empty description round-trips unchanged (positive control)."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"),
        tags={"sim2real": "deployment-description-empty-string-preserved"},
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

    created = apigw.create_deployment(restApiId=api_id, description="")
    deployment_id = created["id"]

    # API Gateway normalizes an explicit '' description away rather than preserving it.
    assert created.get("description") is None, created.get("description")

    got = apigw.get_deployment(restApiId=api_id, deploymentId=deployment_id)
    assert got.get("description") is None, got.get("description")

    # Positive control: a non-empty description DOES round-trip byte-for-byte, proving the
    # normalization above is specific to '' and not a general description-dropping bug.
    non_empty = apigw.create_deployment(restApiId=api_id, description="release notes v1")
    assert non_empty.get("description") == "release notes v1", non_empty.get("description")
    got2 = apigw.get_deployment(restApiId=api_id, deploymentId=non_empty["id"])
    assert got2.get("description") == "release notes v1", got2.get("description")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
