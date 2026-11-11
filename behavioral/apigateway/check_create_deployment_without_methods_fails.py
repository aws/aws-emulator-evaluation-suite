"""create-deployment-without-methods-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-without-methods-fails"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


def _add_method(ag, rest_api_id, resource_id):
    ag.put_method(restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", type="MOCK")


def _deployment_ids(ag, rest_api_id):
    return {d["id"] for d in ag.get_deployments(restApiId=rest_api_id)["items"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment on an API with zero methods is rejected and creates no deployment; the
    identical call succeeds on the same API while it has a method."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)
    root_id = ag.get_resources(restApiId=rest_api_id)["items"][0]["id"]

    _add_method(ag, rest_api_id, root_id)
    first_deployment_id = ag.create_deployment(restApiId=rest_api_id)["id"]
    deployments_with_method = _deployment_ids(ag, rest_api_id)
    assert first_deployment_id in deployments_with_method, (
        f"expected {first_deployment_id} in {deployments_with_method}"
    )

    ag.delete_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET")

    code, message = _error(lambda: ag.create_deployment(restApiId=rest_api_id))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "The REST API doesn't contain any methods", f"unexpected BadRequestException message {message!r}"

    deployments_after_rejection = _deployment_ids(ag, rest_api_id)
    assert deployments_after_rejection == deployments_with_method, (
        f"a rejected CreateDeployment must not create a deployment: "
        f"{deployments_after_rejection - deployments_with_method}"
    )

    _add_method(ag, rest_api_id, root_id)
    second_deployment_id = ag.create_deployment(restApiId=rest_api_id)["id"]
    deployments_final = _deployment_ids(ag, rest_api_id)
    assert second_deployment_id not in deployments_with_method and second_deployment_id in deployments_final, (
        f"expected a new deployment {second_deployment_id} once the method was restored, got {deployments_final}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
