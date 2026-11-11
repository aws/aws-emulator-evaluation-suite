"""stage-variables-empty-map-vs-absent-distinguished."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stage-variables-empty-map-vs-absent-distinguished"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stage created with an explicit empty variables map differs from one with variables omitted."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-stagevar-"),
        tags={"sim2real-check": CHECK},
    )
    rest_api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    resources = apigw.get_resources(restApiId=rest_api_id)
    root_id = resources["items"][0]["id"]

    apigw.put_method(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_method_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    deployment = apigw.create_deployment(
        restApiId=rest_api_id, description="behav-deploy-stagevars"
    )
    deployment_id = deployment["id"]

    stage_empty = ctx.unique_name("sim2realvarsempty")
    stage_absent = ctx.unique_name("sim2realvarsabsent")

    apigw.create_stage(
        restApiId=rest_api_id,
        stageName=stage_empty,
        deploymentId=deployment_id,
        variables={},
    )
    apigw.create_stage(
        restApiId=rest_api_id,
        stageName=stage_absent,
        deploymentId=deployment_id,
    )

    got_empty = apigw.get_stage(restApiId=rest_api_id, stageName=stage_empty)
    got_absent = apigw.get_stage(restApiId=rest_api_id, stageName=stage_absent)

    assert got_empty.get("variables") == {}, (
        f"stage created with explicit empty variables map should read back as {{}}, "
        f"got {got_empty.get('variables')!r}"
    )
    assert "variables" not in got_absent, (
        "stage created with variables omitted should not report a variables map at all, "
        f"got {got_absent.get('variables')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
