"""get-export-integrations-extension-projects-mock-config-only-when-requested."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-export-integrations-extension-projects-mock-config-only-when-requested"
GROUP = "export"
SERVICES = ["apigateway"]


def _delete_rest_api_quota_aware(apigw, api_id, *, budget_s: float = 320.0) -> None:
    """DeleteRestApi is quota'd to one call every 30s per account; retry the throttle."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExport embeds a method's live x-amazon-apigateway-integration block only when the
    export is requested with the extensions=integrations query parameter."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-export-"))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_quota_aware(apigw, api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseModels={"application/json": "Empty"},
    )
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    stage_name = "test"
    deployment_id = apigw.create_deployment(restApiId=api_id, stageName=stage_name)["id"]

    plain = apigw.get_export(
        restApiId=api_id, stageName=stage_name, exportType="oas30", accepts="application/json",
    )
    plain_doc = json.loads(plain["body"].read())
    plain_get = plain_doc["paths"]["/"]["get"]
    assert "x-amazon-apigateway-integration" not in plain_get, (
        f"plain export (no extensions parameter) must not carry the integration block, "
        f"got keys={sorted(plain_get)}"
    )

    with_ext = apigw.get_export(
        restApiId=api_id, stageName=stage_name, exportType="oas30",
        parameters={"extensions": "integrations"}, accepts="application/json",
    )
    ext_doc = json.loads(with_ext["body"].read())
    ext_get = ext_doc["paths"]["/"]["get"]
    integration = ext_get.get("x-amazon-apigateway-integration")
    assert integration is not None, (
        f"extensions=integrations export must carry the live integration block, got keys="
        f"{sorted(ext_get)}"
    )
    assert integration.get("type") == "mock", (
        f"expected the exported integration type to read back as 'mock', got {integration.get('type')!r}"
    )
    assert integration.get("requestTemplates", {}).get("application/json") == '{"statusCode": 200}', (
        f"expected the exported integration to carry the live request template, got "
        f"{integration.get('requestTemplates')!r}"
    )

    # Same deployment, re-read: the projection is a property of the GetExport call, not a
    # one-time effect of the stage's state.
    replayed = apigw.get_export(
        restApiId=api_id, stageName=stage_name, exportType="oas30", accepts="application/json",
    )
    replayed_doc = json.loads(replayed["body"].read())
    assert "x-amazon-apigateway-integration" not in replayed_doc["paths"]["/"]["get"], (
        "re-reading the plain export after requesting extensions=integrations must still omit "
        "the integration block"
    )
    assert deployment_id, "expected a deployment id to have been minted"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
