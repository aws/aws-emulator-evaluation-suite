"""delete-stage-then-get-not-found."""
from __future__ import annotations

import random
import string
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stage-then-get-not-found"
GROUP = 'deployments-stages'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _client_error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS raises, because that is the strongest available signal."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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
        tags={"sim2real": CHECK},
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
    """DeleteStage removes the stage: an independent GetStage returns NotFoundException,
    a further mutation (UpdateStage) on the dead id also fails NotFoundException, and the
    freed stage name is reusable by a fresh CreateStage."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_deployable_api(ctx, ag)
    deployment_id = ag.create_deployment(restApiId=rest_api_id)["id"]
    stage_name = f"s{_unique_token()}"
    ag.create_stage(
        restApiId=rest_api_id, stageName=stage_name, deploymentId=deployment_id
    )

    ag.delete_stage(restApiId=rest_api_id, stageName=stage_name)

    code, message = _client_error(
        lambda: ag.get_stage(restApiId=rest_api_id, stageName=stage_name)
    )
    assert code == "NotFoundException", f"expected NotFoundException on get_stage, got {code}"
    assert message == "Invalid stage identifier specified", message

    # a mutation on the dead id also fails, not just the read
    code, message = _client_error(
        lambda: ag.update_stage(
            restApiId=rest_api_id,
            stageName=stage_name,
            patchOperations=[{"op": "replace", "path": "/description", "value": "x"}],
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException on update_stage of a deleted stage, got {code}"
    assert message == "Invalid stage identifier specified", message

    # the freed stage name is reusable: create_stage with the identical name succeeds again
    ag.create_stage(restApiId=rest_api_id, stageName=stage_name, deploymentId=deployment_id)
    recreated = ag.get_stage(restApiId=rest_api_id, stageName=stage_name)
    assert recreated["stageName"] == stage_name, (
        f"expected the freed stage name {stage_name!r} to be reusable, got {recreated.get('stageName')!r}"
    )
    ag.delete_stage(restApiId=rest_api_id, stageName=stage_name)
    code, message = _client_error(
        lambda: ag.get_stage(restApiId=rest_api_id, stageName=stage_name)
    )
    assert code == "NotFoundException", f"expected NotFoundException after final delete, got {code}"
    assert message == "Invalid stage identifier specified", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
