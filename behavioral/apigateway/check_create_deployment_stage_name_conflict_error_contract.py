"""create-deployment-stage-name-conflict-error-contract."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-deployment-stage-name-conflict-error-contract"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStage reusing an existing stage name, even with a different deployment, fails with
    ConflictException and leaves the stage on its original deployment, while an unused stage name succeeds."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"),
        tags={"sim2real": "create-deployment-stage-name-conflict-error-contract"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = _root_resource_id(apigw, api_id)
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="ping")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200", responseTemplates={}
    )

    deployment0_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "orig"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment0_id)

    # A second, independent deployment snapshot -- NOT wired to any stage yet.
    deployment1_id = apigw.create_deployment(restApiId=api_id)["id"]

    code, message = _client_error(
        lambda: apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment1_id),
        context="stage-name collision",
    )
    assert code == "ConflictException", f"expected ConflictException on stage-name collision, got {code}"
    assert message == "Stage already exists", f"unexpected ConflictException message {message!r}"

    # Effect absent: the existing stage must still point at the original deployment.
    stage_after = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage_after["deploymentId"] == deployment0_id, (
        f"stage '{stage_name}' deploymentId changed from {deployment0_id} to {stage_after['deploymentId']}"
    )

    # Positive control: a fresh stage name pointing at the second deployment creates cleanly.
    new_stage_name = "fresh"
    apigw.create_stage(restApiId=api_id, stageName=new_stage_name, deploymentId=deployment1_id)
    stage_new = apigw.get_stage(restApiId=api_id, stageName=new_stage_name)
    assert stage_new["deploymentId"] == deployment1_id, (
        f"positive-control stage '{new_stage_name}' expected deploymentId {deployment1_id}, "
        f"got {stage_new['deploymentId']}"
    )


def _root_resource_id(apigw: Any, api_id: str) -> str:
    for item in apigw.get_resources(restApiId=api_id)["items"]:
        if item["path"] == "/":
            return item["id"]
    raise AssertionError("root resource not found")


def _client_error(fn: Callable[[], Any], *, context: str) -> tuple[str, str]:
    """Call fn(); return its botocore Error (code, message). An unexpected success raises, so an
    accepted call is reported as accepted rather than as a wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (err.response["Error"]["Code"], err.response["Error"].get("Message", ""))
    raise AssertionError(f"real AWS rejects this call ({context}), but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
