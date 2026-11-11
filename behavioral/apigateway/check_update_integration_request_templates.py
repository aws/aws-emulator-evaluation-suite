"""update-integration-request-templates."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-integration-request-templates"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Patch updates to integration requestTemplates/timeoutInMillis and integration response templates land."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _best_effort(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": "{}"}, timeoutInMillis=29000,
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": '{"original": true}'},
    )

    before = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert before["timeoutInMillis"] == 29000, before.get("timeoutInMillis")
    assert before["requestTemplates"]["application/json"] == "{}", before["requestTemplates"]

    apigw.update_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET",
        patchOperations=[
            {"op": "replace", "path": "/requestTemplates/application~1json", "value": '{"statusCode": 200}'},
            {"op": "replace", "path": "/timeoutInMillis", "value": "5000"},
        ],
    )

    after = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert after["timeoutInMillis"] == 5000, (
        f"expected timeoutInMillis=5000 after UpdateIntegration patch, got {after.get('timeoutInMillis')}"
    )
    assert after["requestTemplates"]["application/json"] == '{"statusCode": 200}', (
        f"expected patched requestTemplates, got {after['requestTemplates']}"
    )

    apigw.update_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        patchOperations=[
            {"op": "replace", "path": "/responseTemplates/application~1json", "value": '{"updated": true}'}
        ],
    )

    integration_response = apigw.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert integration_response["responseTemplates"]["application/json"] == '{"updated": true}', (
        f"expected patched responseTemplates via independent GetIntegrationResponse read, "
        f"got {integration_response['responseTemplates']}"
    )


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
