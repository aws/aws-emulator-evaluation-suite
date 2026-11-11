"""get-deployment-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deployment-nonexistent-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises, because a target accepting a call real AWS refuses must not be
    reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDeployment returns a real deployment on the API (positive control) and fails with
    NotFoundException for a bogus deploymentId, so the refusal is attributable to the id."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)

    root_id = ag.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    ag.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    # positive control: a real deployment is created and independently retrievable
    deployment_id = ag.create_deployment(restApiId=rest_api_id)["id"]
    got = ag.get_deployment(restApiId=rest_api_id, deploymentId=deployment_id)
    assert got["id"] == deployment_id, f"expected deployment {deployment_id!r}, got {got.get('id')!r}"

    code, message = _error(
        lambda: ag.get_deployment(restApiId=rest_api_id, deploymentId="bogusdeployment")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Deployment identifier specified", (
        f"unexpected NotFoundException message {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
