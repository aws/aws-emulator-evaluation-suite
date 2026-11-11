"""stage-variables-empty-vs-absent-preserved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stage-variables-empty-vs-absent-preserved"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stage variable value of '' is rejected outright by CreateStage (API Gateway forbids
    empty-string stage variable values), while a variable that was simply never set is absent
    from GetStage — distinct failure/absence shapes for two different "no value" cases.
    """
    apigw = ctx.client("apigateway")

    api_id, _root_id, deployment_id = _create_deployed_rest_api(ctx)

    stage_name = "prod"

    # Empty-string stage variable value: CreateStage must reject it (BadRequestException),
    # not silently accept and store ''.
    empty_key = "emptyVar"
    code, message = _error(
        lambda: apigw.create_stage(
            restApiId=api_id,
            stageName=stage_name,
            deploymentId=deployment_id,
            variables={empty_key: ""},
        )
    )
    assert code == "BadRequestException", code
    assert message == (
        f"Invalid stage variable value of key {empty_key}.  Please use values with alphanumeric "
        "characters and the symbols ' ', -', '.', '_', ':', '/', '?', '&', '=', and ','."
    ), f"unexpected message: {message!r}"

    # Effect absent: the rejected create_stage call must not have left a partial stage behind.
    not_created, not_created_message = _error(
        lambda: apigw.get_stage(restApiId=api_id, stageName=stage_name)
    )
    assert not_created == "NotFoundException", not_created
    assert not_created_message == "Invalid stage identifier specified", (
        f"unexpected message: {not_created_message!r}"
    )

    # Positive control: a stage with a valid non-empty variable succeeds, and a key that was
    # never set is simply absent from the variables map (not present with an empty value).
    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        variables={"presentVar": "hello"},
    )
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    got = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    variables = got.get("variables", {})
    assert variables.get("presentVar") == "hello", variables
    assert "neverSetVar" not in variables, variables


def _error(fn):
    """Call fn(); return its (Code, Message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_deployed_rest_api(ctx, description: str = ""):
    """Create a REST API with a mock GET method on the root resource and one deployment."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
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
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200", selectionPattern=""
    )
    deployment_id = apigw.create_deployment(restApiId=api_id, description=description)["id"]
    return api_id, root_id, deployment_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
