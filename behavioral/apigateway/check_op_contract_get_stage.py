"""op-contract-getStage."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-getStage"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetStage reflects the deploymentId and stage variables set at deployment
    time; a lookup of a nonexistent stage name 404s."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    stage_name = "prod"
    deployment = apigw.create_deployment(
        restApiId=api_id, stageName=stage_name, variables={"env": "test-value"}
    )
    deployment_id = deployment["id"]

    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage["stageName"] == stage_name, f"expected stageName={stage_name!r}, got {stage['stageName']!r}"
    assert stage["deploymentId"] == deployment_id, (
        f"expected deploymentId={deployment_id!r}, got {stage['deploymentId']!r}"
    )
    assert stage["variables"] == {"env": "test-value"}, (
        f"expected variables={{'env': 'test-value'}}, got {stage['variables']!r}"
    )

    code, message = _error(lambda: apigw.get_stage(restApiId=api_id, stageName="nonexistent-stage"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "Invalid stage identifier specified", f"unexpected message: {message!r}"


def _error(fn) -> Any:
    """Call fn(); return botocore's (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator accepting a lookup real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
