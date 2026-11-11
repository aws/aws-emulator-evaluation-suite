"""delete-deployment-referenced-by-stage-conflict."""
from __future__ import annotations

import random
import string
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-deployment-referenced-by-stage-conflict"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")

def _ignore_not_found(fn):
    """Best-effort call that tolerates the target already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _put_basic_method(ag, api_id, resource_id, http_method="GET"):
    """A fully integrated MOCK method (deployable without a real backend)."""
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                  authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                       type="MOCK", requestTemplates={"application/json": '{"statusCode": 200}'})
    ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                           statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                                statusCode="200")

def _create_deployable_api(ctx, ag):
    """Create a REST API that carries one deployable (integrated) mock GET method."""
    api_id = _create_api(ctx, ag)
    _put_basic_method(ag, api_id, _root_id(ag, api_id), "GET")
    return api_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeployment on the deployment a stage points at fails with BadRequestException ("Active stages
    pointing to this deployment must be moved or deleted"); once the stage is removed the identical
    delete succeeds and the deployment is gone."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_deployable_api(ctx, ag)
    deployment_id = ag.create_deployment(restApiId=rest_api_id)["id"]
    stage_name = f"s{_unique_token()}"
    ag.create_stage(
        restApiId=rest_api_id, stageName=stage_name, deploymentId=deployment_id
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: ag.delete_stage(restApiId=rest_api_id, stageName=stage_name))
    )

    code, message = _error(
        lambda: ag.delete_deployment(restApiId=rest_api_id, deploymentId=deployment_id)
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Active stages pointing to this deployment must be moved or deleted", f"unexpected active-stage message: {message!r}"

    # independent read: the rejected delete must not have taken effect.
    still_there = ag.get_deployment(restApiId=rest_api_id, deploymentId=deployment_id)
    assert still_there["id"] == deployment_id, (
        f"deployment {deployment_id} not intact after a delete that should have been rejected"
    )

    # restore: once nothing points at it, the identical delete call succeeds.
    ag.delete_stage(restApiId=rest_api_id, stageName=stage_name)
    ag.delete_deployment(restApiId=rest_api_id, deploymentId=deployment_id)

    code, message = _error(
        lambda: ag.get_deployment(restApiId=rest_api_id, deploymentId=deployment_id)
    )
    assert code == "NotFoundException", f"deployment still present after delete, got {code}"
    assert message == "Invalid Deployment identifier specified", f"unexpected not-found message: {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
