"""stage-variables-empty-map-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stage-variables-empty-map-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetStage returns `variables` as an empty map for a stage created with variables={}, and omits
    the field entirely for a stage created without variables."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)
    deployment_id = _deploy_minimal_api(ctx, apigw, api_id)

    stage_explicit_empty = ctx.unique_name("stgEmpty").replace("-", "")
    stage_no_variables = ctx.unique_name("stgAbsent").replace("-", "")

    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_explicit_empty,
        deploymentId=deployment_id,
        variables={},
    )
    ctx.on_cleanup(
        lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_explicit_empty)
    )

    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_no_variables,
        deploymentId=deployment_id,
    )
    ctx.on_cleanup(
        lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_no_variables)
    )

    resp_empty = apigw.get_stage(restApiId=api_id, stageName=stage_explicit_empty)
    resp_absent = apigw.get_stage(restApiId=api_id, stageName=stage_no_variables)

    assert "variables" in resp_empty and resp_empty["variables"] == {}, (
        f"explicit empty variables map was not preserved: {resp_empty.get('variables')!r}"
    )
    assert "variables" not in resp_absent, (
        f"stage created without variables should have no variables field, got {resp_absent.get('variables')!r}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-apigw-")
    resp = apigw.create_rest_api(name=name, tags={"sim2real-check": CHECK})
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


def _deploy_minimal_api(ctx, apigw, api_id):
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    deployment = apigw.create_deployment(restApiId=api_id)
    return deployment["id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
