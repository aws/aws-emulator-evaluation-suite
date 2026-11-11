"""op-contract-getExport."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-getExport"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExport(exportType='swagger') returns an OpenAPI document that reflects
    the deployed resource/method; an unsupported exportType is rejected."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")
    resource_id = resource["id"]

    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )

    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    export = apigw.get_export(
        restApiId=api_id, stageName=stage_name, exportType="swagger", accepts="application/json"
    )
    # The "accepts" parameter only selects the serialization of the exported
    # document body; real AWS still reports the transport contentType as
    # "application/octet-stream" (it's a generic file download), not the
    # accepted media type. Assert against that actual behavior instead.
    assert export["contentType"] == "application/octet-stream", export["contentType"]
    body = export["body"].read()
    doc = json.loads(body)
    assert doc.get("swagger") == "2.0", f"expected a swagger 2.0 document, got {doc.get('swagger')!r}"
    assert "/items" in doc["paths"], f"expected '/items' in exported paths, got {list(doc['paths'])}"
    assert "get" in doc["paths"]["/items"], (
        f"expected the deployed GET method under '/items', got {list(doc['paths']['/items'])}"
    )

    code, message = _error(
        lambda: apigw.get_export(restApiId=api_id, stageName=stage_name, exportType="not-a-real-type")
    )
    assert code == "BadRequestException", code
    assert message == "No API exporter for type 'not-a-real-type'", message


def _error(fn) -> Any:
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
