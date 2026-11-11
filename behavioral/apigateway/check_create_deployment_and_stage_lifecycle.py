"""create-deployment-and-stage-lifecycle."""
from __future__ import annotations

import random
import string

from behavioral_harness import tags

CHECK = "create-deployment-and-stage-lifecycle"
GROUP = 'deployments-stages'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

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


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """CreateDeployment followed by CreateStage links deploymentId onto GetStage;
    DeleteStage then makes the stage unreadable and unmutable by the same name."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_deployable_api(ctx, ag)
    deployment_id = ag.create_deployment(restApiId=rest_api_id)["id"]

    stage_name = f"s{_unique_token()}"
    ag.create_stage(
        restApiId=rest_api_id, stageName=stage_name, deploymentId=deployment_id
    )

    stage = ag.get_stage(restApiId=rest_api_id, stageName=stage_name)
    assert stage["deploymentId"] == deployment_id, (
        f"expected deploymentId {deployment_id}, got {stage['deploymentId']}"
    )

    ag.delete_stage(restApiId=rest_api_id, stageName=stage_name)

    read_code, read_message = _error(lambda: ag.get_stage(restApiId=rest_api_id, stageName=stage_name))
    assert read_code == "NotFoundException", (
        f"expected NotFoundException reading a deleted stage, got {read_code!r}"
    )
    assert read_message == "Invalid stage identifier specified", f"unexpected NotFoundException message {read_message!r}"

    mutate_code, mutate_message = _error(lambda: ag.update_stage(
        restApiId=rest_api_id, stageName=stage_name,
        patchOperations=[{"op": "replace", "path": "/description", "value": "x"}],
    ))
    assert mutate_code == "NotFoundException", (
        f"expected NotFoundException patching a deleted stage, got {mutate_code!r}"
    )
    assert mutate_message == "Invalid stage identifier specified", f"unexpected NotFoundException message {mutate_message!r}"


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
