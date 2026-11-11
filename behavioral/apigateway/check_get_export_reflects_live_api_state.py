"""get-export-reflects-live-api-state."""
from __future__ import annotations

import json
import random
import string

from behavioral_harness import tags

CHECK = "get-export-reflects-live-api-state"
GROUP = 'rest-api'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

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
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _put_mock_method(ag, api_id, resource_id, http_method="GET"):
    """A fully integrated MOCK method (deployable without a real backend)."""
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                  authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                       type="MOCK", requestTemplates={"application/json": '{"statusCode": 200}'})
    ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                           statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                                statusCode="200", responseTemplates={"application/json": '{"message": "ok"}'})


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExport reflects the deployment a stage currently points at: a new resource appears in the
    stage's Swagger export only after the stage is repointed at a deployment that includes it."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    widgets_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]
    _put_mock_method(ag, api_id, widgets_id, "GET")
    deployment_1 = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(restApiId=api_id, stageName="prod", deploymentId=deployment_1)

    export_1 = ag.get_export(restApiId=api_id, stageName="prod", exportType="swagger")
    doc_1 = json.loads(
        export_1["body"].read() if hasattr(export_1["body"], "read") else export_1["body"]
    )
    assert "/widgets" in doc_1.get("paths", {}), (
        f"expected the exported swagger doc to contain the real '/widgets' path, "
        f"got paths={list(doc_1.get('paths', {}))!r}"
    )
    assert "get" in doc_1["paths"]["/widgets"], (
        f"expected '/widgets' to include the configured GET method, got {doc_1['paths']['/widgets']!r}"
    )
    assert "/gadgets" not in doc_1.get("paths", {}), (
        "expected the FIRST export to not yet contain the not-yet-deployed '/gadgets' path"
    )

    gadgets_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="gadgets")["id"]
    _put_mock_method(ag, api_id, gadgets_id, "POST")

    # 'prod' is still pinned to deployment_1, which predates '/gadgets'; the export must come from
    # the deployment snapshot, not the live resource tree.
    export_interim = ag.get_export(restApiId=api_id, stageName="prod", exportType="swagger")
    doc_interim = json.loads(
        export_interim["body"].read() if hasattr(export_interim["body"], "read") else export_interim["body"]
    )
    assert "/gadgets" not in doc_interim.get("paths", {}), (
        f"expected '/gadgets' to stay absent while stage 'prod' is still pinned to deployment_1 "
        f"(predates '/gadgets'), got paths={list(doc_interim.get('paths', {}))!r}"
    )

    deployment_2 = ag.create_deployment(restApiId=api_id)["id"]
    ag.update_stage(
        restApiId=api_id,
        stageName="prod",
        patchOperations=[{"op": "replace", "path": "/deploymentId", "value": deployment_2}],
    )

    export_2 = ag.get_export(restApiId=api_id, stageName="prod", exportType="swagger")
    doc_2 = json.loads(
        export_2["body"].read() if hasattr(export_2["body"], "read") else export_2["body"]
    )
    assert "/gadgets" in doc_2.get("paths", {}), (
        f"expected the SECOND export (after repointing the stage at deployment_2) to reflect "
        f"the newly deployed '/gadgets' path, got paths={list(doc_2.get('paths', {}))!r}"
    )
    assert "post" in doc_2["paths"]["/gadgets"], (
        f"expected '/gadgets' to include its configured POST method, got {doc_2['paths']['/gadgets']!r}"
    )
    assert "/widgets" in doc_2.get("paths", {}), (
        "expected the still-live '/widgets' path to remain present in the second export"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
