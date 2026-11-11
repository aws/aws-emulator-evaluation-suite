"""update-integration-response-patch-templates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-integration-response-patch-templates"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIntegrationResponse patches responseTemplates for a given status code mapping."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    created = apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": "{}"},
    )
    assert created["statusCode"] == "200", f"expected statusCode 200 on create, got {created.get('statusCode')!r}"
    assert created["responseTemplates"]["application/json"] == "{}", (
        f"expected the seeded template on create, got {created['responseTemplates'].get('application/json')!r}"
    )

    updated = apigw.update_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        patchOperations=[
            {"op": "replace", "path": "/responseTemplates/application~1json", "value": '{"ok": true}'}
        ],
    )
    assert updated["statusCode"] == "200", "UpdateIntegrationResponse must not change the status code mapping key"
    assert updated["responseTemplates"]["application/json"] == '{"ok": true}', (
        f"expected the patched template in UpdateIntegrationResponse's own response, "
        f"got {updated['responseTemplates'].get('application/json')!r}"
    )

    fetched = apigw.get_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    assert fetched["responseTemplates"]["application/json"] == '{"ok": true}', (
        f"independent GetIntegrationResponse must reflect the patch, "
        f"got {fetched['responseTemplates'].get('application/json')!r}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-bh-api-"),
        tags={"sim2real": "update-integration-response-patch-templates"},
    )
    api_id = resp["id"]
    root_id = resp["rootResourceId"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
