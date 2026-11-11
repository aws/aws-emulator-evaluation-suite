"""op-contract-deleteDeployment."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deleteDeployment"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeployment is rejected with BadRequestException while a stage still points at the
    deployment; once the stage is removed the same delete succeeds and the deployment is gone."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
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

    # --- Positive control: DeleteDeployment succeeds on a deployment no stage
    #     references, so the rejection asserted below is specific to the
    #     stage-reference conflict rather than a target that rejects every delete.
    control_id = apigw.create_deployment(restApiId=api_id, description="positive control")["id"]
    apigw.delete_deployment(restApiId=api_id, deploymentId=control_id)
    control = _client_error(lambda: apigw.get_deployment(restApiId=api_id, deploymentId=control_id))
    assert control.get("Code") == "NotFoundException", f"positive control: expected an unreferenced deployment to be deletable, got {control.get('Code')!r}"
    assert control.get("Message") == "Invalid Deployment identifier specified", (
        f"expected the exact NotFound message for the deleted control deployment, got {control.get('Message')!r}"
    )

    deployment = apigw.create_deployment(restApiId=api_id, description="behavioral check")
    deployment_id = deployment["id"]
    assert deployment_id, f"expected create_deployment to return an id, got {deployment!r}"

    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))
    )

    err = _client_error(lambda: apigw.delete_deployment(restApiId=api_id, deploymentId=deployment_id))
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException while stage exists, got {err.get('Code')!r}"
    assert err.get("Message") == "Active stages pointing to this deployment must be moved or deleted", (
        f"expected the exact active-stage message, got {err.get('Message')!r}"
    )

    still_there = apigw.get_deployment(restApiId=api_id, deploymentId=deployment_id)
    assert still_there["id"] == deployment_id, (
        f"expected the rejected delete to leave the deployment in place, got {still_there!r}"
    )

    apigw.delete_stage(restApiId=api_id, stageName=stage_name)
    apigw.delete_deployment(restApiId=api_id, deploymentId=deployment_id)

    err = _client_error(lambda: apigw.get_deployment(restApiId=api_id, deploymentId=deployment_id))
    assert err.get("Code") == "NotFoundException", f"deployment still present after delete, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Deployment identifier specified", (
        f"expected the exact NotFound message from GetDeployment, got {err.get('Message')!r}"
    )

    # --- A mutation on the dead id must also fail, not silently succeed or
    #     resurrect the deployment.
    err = _client_error(lambda: apigw.delete_deployment(restApiId=api_id, deploymentId=deployment_id))
    assert err.get("Code") == "NotFoundException", f"double-delete of a gone deployment, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Deployment identifier specified", (
        f"expected the exact NotFound message from DeleteDeployment, got {err.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
