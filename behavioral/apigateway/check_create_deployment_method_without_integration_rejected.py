"""create-deployment-method-without-integration-rejected."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-method-without-integration-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _deployment_ids(ag, rest_api_id):
    return {
        d["id"]
        for page in ag.get_paginator("get_deployments").paginate(restApiId=rest_api_id)
        for d in page.get("items", [])
    }


def _retry_throttled(fn, *, attempts=4, base_delay=5.0):
    """Call fn(), retrying only TooManyRequestsException (DeleteRestApi allows one request every
    30 s per account) with jittered backoff."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(base_delay * (attempt + 1) + random.uniform(0, 0.5))


def _put_mock_integration(ag, rest_api_id, resource_id):
    ag.put_integration(restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
                        requestTemplates={"application/json": '{"statusCode": 200}'})
    ag.put_integration_response(restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET",
                                 statusCode="200", responseTemplates={"application/json": "{}"})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment is rejected with the exact BadRequestException when a defined method
    has no integration, creates no deployment, and the identical call succeeds once the
    integration is wired up and fails again once it is removed."""
    ag = ctx.client("apigateway")
    rest_api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-noint-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=rest_api_id)))

    root_id = ag.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    ag.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")

    deployments_before = _deployment_ids(ag, rest_api_id)
    code, message = _error(lambda: ag.create_deployment(restApiId=rest_api_id))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}: {message!r}"
    assert message == "No integration defined for method", f"unexpected message {message!r}"

    deployments_after_rejection = _deployment_ids(ag, rest_api_id)
    assert deployments_after_rejection == deployments_before, (
        f"a rejected CreateDeployment must not create a deployment: "
        f"{deployments_after_rejection - deployments_before}"
    )

    # Positive control: the identical call succeeds once the method has an integration.
    _put_mock_integration(ag, rest_api_id, root_id)
    wired_deployment_id = ag.create_deployment(restApiId=rest_api_id)["id"]
    deployments_with_integration = _deployment_ids(ag, rest_api_id)
    assert wired_deployment_id in deployments_with_integration, (
        f"expected {wired_deployment_id} in {deployments_with_integration}"
    )

    # Remove the integration again: the failure is attributable to the missing integration
    # alone, not a one-time condition of a freshly created method.
    ag.delete_integration(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET")
    code, message = _error(lambda: ag.create_deployment(restApiId=rest_api_id))
    assert code == "BadRequestException", f"expected BadRequestException again, got {code!r}: {message!r}"
    assert message == "No integration defined for method", f"unexpected message on second rejection {message!r}"

    deployments_final = _deployment_ids(ag, rest_api_id)
    assert deployments_final == deployments_with_integration, (
        f"the second rejected CreateDeployment must not create a deployment either: "
        f"{deployments_final - deployments_with_integration}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
