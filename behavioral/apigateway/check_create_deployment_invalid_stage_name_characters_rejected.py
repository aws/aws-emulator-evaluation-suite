"""create-deployment-invalid-stage-name-characters-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "create-deployment-invalid-stage-name-characters-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment rejects a stageName with characters outside [A-Za-z0-9_-]."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    _make_deployable_method(apigw, api_id, root_id, "GET")

    bad_stage = "bad stage!"
    # Negative: space and "!" are disallowed in stage names.
    code, message = _error(
        lambda: apigw.create_deployment(restApiId=api_id, stageName=bad_stage)
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Stage name only allows a-zA-Z0-9_", f"unexpected BadRequestException message {message!r}"

    # Effect absent: the malformed stage must not exist.
    absent_code, absent_message = _error(lambda: apigw.get_stage(restApiId=api_id, stageName=bad_stage))
    assert absent_code == "NotFoundException", f"stage leaked despite bad name: {absent_code}"
    assert absent_message == "Invalid stage identifier specified", f"unexpected NotFoundException message {absent_message!r}"

    # Positive control: a valid stage name (alphanumeric, hyphen, underscore) succeeds.
    good_stage = "good-stage_1"
    apigw.create_deployment(restApiId=api_id, stageName=good_stage)
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=good_stage))
    stage = apigw.get_stage(restApiId=api_id, stageName=good_stage)
    assert stage["stageName"] == good_stage


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
