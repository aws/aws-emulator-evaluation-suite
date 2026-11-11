"""create-duplicate-stage-conflict."""
from __future__ import annotations

import random
import string
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-duplicate-stage-conflict"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

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
    """Creating a stage with a name that already exists on the API must conflict (overly-permissive check)."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_deployable_api(ctx, ag)
    deployment_id = ag.create_deployment(restApiId=rest_api_id)["id"]
    stage_name = f"s{_unique_token()}"
    # Positive control: the first create_stage succeeds cleanly.
    created = ag.create_stage(
        restApiId=rest_api_id, stageName=stage_name, deploymentId=deployment_id
    )

    # Break: the identical call, reusing the now-taken stage name, must conflict.
    code, message = _error(
        lambda: ag.create_stage(
            restApiId=rest_api_id, stageName=stage_name, deploymentId=deployment_id
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == "Stage already exists", f"unexpected ConflictException message {message!r}"

    # Effect absent: an independent read shows no second stage was created, and the
    # original stage's creation timestamp is untouched by the rejected duplicate.
    matching = [
        s for s in ag.get_stages(restApiId=rest_api_id)["item"]
        if s["stageName"] == stage_name
    ]
    assert len(matching) == 1, (
        f"expected exactly one stage named {stage_name!r} after the rejected duplicate, "
        f"found {len(matching)}"
    )
    assert matching[0]["createdDate"] == created["createdDate"], (
        f"rejected duplicate create_stage must not alter the existing stage: expected "
        f"createdDate {created['createdDate']!r}, got {matching[0]['createdDate']!r}"
    )

    # Restore: freeing the name lets the identical call succeed, proving the conflict was
    # about the name collision and not some other, permanent defect in the request.
    ag.delete_stage(restApiId=rest_api_id, stageName=stage_name)
    ag.create_stage(
        restApiId=rest_api_id, stageName=stage_name, deploymentId=deployment_id
    )
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=rest_api_id, stageName=stage_name))

    # Terminal read: independent read at the destination confirms the restored stage is live.
    restored = ag.get_stage(restApiId=rest_api_id, stageName=stage_name)
    assert restored["deploymentId"] == deployment_id, (
        f"expected the recreated stage to bind deploymentId {deployment_id!r}, "
        f"got {restored['deploymentId']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
