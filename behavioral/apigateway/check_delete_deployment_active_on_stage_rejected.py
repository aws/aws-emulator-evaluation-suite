"""delete-deployment-active-on-stage-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-deployment-active-on-stage-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a deployment that is still active on a stage must be rejected, not silently
    allowed; once the blocking stage is gone, the identical delete must succeed and the
    deployment must become unreachable."""
    apigw = ctx.client("apigateway")
    api_id, _root_id = _create_deployable_api(ctx)

    deployment_id = apigw.create_deployment(restApiId=api_id, description="active-deployment")["id"]
    apigw.create_stage(restApiId=api_id, stageName="prod", deploymentId=deployment_id)
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_stage(restApiId=api_id, stageName="prod")))

    code, message, status = _error(lambda: apigw.delete_deployment(restApiId=api_id, deploymentId=deployment_id))
    assert code == "BadRequestException", (
        f"expected BadRequestException deleting a deployment active on a stage, got {code}"
    )
    assert status == 400, f"expected HTTP 400 deleting a deployment active on a stage, got {status!r}"
    expected_message = "Active stages pointing to this deployment must be moved or deleted"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # the delete was rejected: an independent read must still find the deployment.
    still_there = apigw.get_deployment(restApiId=api_id, deploymentId=deployment_id)
    assert still_there["id"] == deployment_id, (
        f"deployment {deployment_id} is gone despite the rejected delete"
    )

    # restore: remove the blocking stage, then the identical delete must now succeed.
    apigw.delete_stage(restApiId=api_id, stageName="prod")
    apigw.delete_deployment(restApiId=api_id, deploymentId=deployment_id)

    # Beat 1: the by-id read is NotFoundException 404.
    code, message, status = _error(lambda: apigw.get_deployment(restApiId=api_id, deploymentId=deployment_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException reading the deployment after its unblocked delete, got {code}"
    )
    assert status == 404, f"expected HTTP 404 reading the deleted deployment, got {status!r}"
    expected_message = "Invalid Deployment identifier specified"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Beat 2: the deployment is absent from the API's deployment listing.
    listed = [
        d.get("id")
        for page in apigw.get_paginator("get_deployments").paginate(restApiId=api_id)
        for d in page.get("items", [])
    ]
    assert deployment_id not in listed, f"deleted deployment still listed by GetDeployments: {listed!r}"

    # Beat 3: a mutation on the dead id is refused.
    code, message, status = _error(lambda: apigw.update_deployment(
        restApiId=api_id, deploymentId=deployment_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "post-delete"}],
    ))
    assert code == "NotFoundException", f"expected NotFoundException updating the deleted deployment, got {code}"
    assert status == 404, f"expected HTTP 404 updating the deleted deployment, got {status!r}"
    expected_message = "Invalid Deployment identifier specified"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message, HTTP status).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_deployable_api(ctx):
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real-check": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
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
