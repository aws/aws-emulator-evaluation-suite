"""update-stage-invalid-tracing-config-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-stage-invalid-tracing-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStage rejects an unsupported PATCH op targeting /tracingEnabled."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    _make_deployable_method(apigw, api_id, root_id, "GET")

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "teststage"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    before = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert before.get("tracingEnabled", False) is False, (
        f"expected a fresh stage to start with tracingEnabled False, got {before.get('tracingEnabled')!r}"
    )

    # Negative: "increment" is not a supported PATCH op for API Gateway.
    err = _client_error(
        lambda: apigw.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[{"op": "increment", "path": "/tracingEnabled", "value": "true"}],
        )
    )
    assert err.get("Code") == "ValidationException", f"expected ValidationException, got {err.get('Code')!r}"
    assert err.get("Message") == (
        "1 validation error detected: Value 'increment' at 'updateStageInput.patchOperations.1.member.op' "
        "failed to satisfy constraint: Member must satisfy enum value set: "
        "[add, remove, move, test, replace, copy]"
    ), f"expected the exact patch-op validation message, got {err.get('Message')!r}"

    # Effect absent: tracingEnabled must remain unchanged.
    after = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert after.get("tracingEnabled", False) is False, "tracingEnabled changed despite rejected patch"

    # Positive control: a valid boolean string patch succeeds.
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[{"op": "replace", "path": "/tracingEnabled", "value": "true"}],
    )
    updated = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert updated["tracingEnabled"] is True, (
        f"expected a valid replace patch to flip tracingEnabled to True, got {updated['tracingEnabled']!r}"
    )


def _client_error(fn: Any) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting a PATCH op real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _make_deployable_method(apigw: Any, api_id: str, resource_id: str, http_method: str) -> None:
    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
