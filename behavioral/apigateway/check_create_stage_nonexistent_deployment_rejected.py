"""create-stage-nonexistent-deployment-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "create-stage-nonexistent-deployment-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStage referencing a deploymentId that doesn't exist is rejected as BadRequest."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    _make_deployable_method(apigw, api_id, root_id, "GET")

    real_deployment_id = apigw.create_deployment(restApiId=api_id)["id"]

    # A syntactically well-formed deployment id (same charset/length as a real one)
    # that does not exist on this RestApi -- distinct from a malformed-id BadRequest.
    fake_deployment_id = _mutate_id(real_deployment_id)

    bad_stage = "badstage"
    # Negative: deploymentId does not exist on this RestApi. Empirically, API
    # Gateway reports this as BadRequestException (not NotFoundException).
    code, message = _error(
        lambda: apigw.create_stage(
            restApiId=api_id,
            stageName=bad_stage,
            deploymentId=fake_deployment_id,
        )
    )
    assert code == "BadRequestException", f"CODE={code}"
    expected = "Deployment id does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the stage must not have been created.
    absent_code, absent_message = _error(lambda: apigw.get_stage(restApiId=api_id, stageName=bad_stage))
    assert absent_code == "NotFoundException", f"stage leaked despite bad deploymentId: {absent_code}"
    expected = "Invalid stage identifier specified"
    assert absent_message == expected, f"expected message {expected!r}, got {absent_message!r}"

    # Positive control: a real deploymentId creates the stage successfully.
    good_stage = "goodstage"
    apigw.create_stage(restApiId=api_id, stageName=good_stage, deploymentId=real_deployment_id)
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=good_stage))
    stage = apigw.get_stage(restApiId=api_id, stageName=good_stage)
    assert stage["deploymentId"] == real_deployment_id, (
        f"expected={real_deployment_id} actual={stage['deploymentId']}"
    )


def _error(fn: Any) -> tuple:
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _make_deployable_method(apigw: Any, api_id: str, resource_id: str, http_method: str) -> None:
    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200"
    )


def _mutate_id(deployment_id: str) -> str:
    """Flip the last character of a real id to build a same-shaped, nonexistent id."""
    last = deployment_id[-1]
    for candidate in "abcdefghijkmnpqrstuvwxyz23456789":
        if candidate != last:
            return deployment_id[:-1] + candidate
    return deployment_id[:-1] + ("z" if last != "z" else "y")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
