"""stage-variables-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stage-variables-unicode-value-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Stage variables with every allowed special character and a unicode description round-trip
    exactly through create, update and get, and a removed variable is absent, not an empty string
    (variable values may not contain unicode)."""
    apigw = ctx.client("apigateway")
    api_id, resource_id = _create_api_with_root_method(ctx)
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]

    unicode_description = "Ünïcödé stage: 説明テキスト, áccents"
    special_value = "v1.0-build_42~rel:2024/09?x=1&y=2,ok"
    stage_name = "teststage"

    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        description=unicode_description,
        variables={"present_var": special_value},
        tags={"sim2real": "stage-variables-unicode-value-round-trip"},
    )
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    got = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert got["description"] == unicode_description, (
        f"expected description {unicode_description!r}, got {got.get('description')!r}"
    )
    assert got["variables"]["present_var"] == special_value, (
        f"expected present_var={special_value!r}, got {got['variables'].get('present_var')!r}"
    )

    # Add a second variable, then remove the first -- absence must be distinct from "".
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/variables/added_var", "value": "second-value_2"},
        ],
    )
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[{"op": "remove", "path": "/variables/present_var"}],
    )

    got2 = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    variables = got2.get("variables", {})
    assert variables.get("added_var") == "second-value_2", (
        f"expected added_var=second-value_2, got {variables.get('added_var')!r}"
    )
    assert "present_var" not in variables, (
        f"removed variable must be fully absent, not empty-string, got {variables.get('present_var')!r}"
    )


def _create_api_with_root_method(ctx) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real": "stage-variables-unicode-value-round-trip"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    resources = apigw.get_resources(restApiId=api_id)["items"]
    root_id = next(r["id"] for r in resources if r["path"] == "/")

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": ""},
    )
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
