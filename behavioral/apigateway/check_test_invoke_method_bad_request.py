"""test-invoke-method-bad-request."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-invoke-method-bad-request"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "test-invoke-method-bad-request"},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeMethod returns 200 with the MOCK body for a body that matches the method's validated
    JSON-schema model, and 400 for one that violates it."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]

    model_name = "Sim2realBehav" + ctx.unique_name("").replace("-", "")
    ag.create_model(
        restApiId=api_id,
        name=model_name,
        contentType="application/json",
        schema=json.dumps(
            {
                "$schema": "http://json-schema.org/draft-04/schema#",
                "title": model_name,
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            }
        ),
    )
    validator = ag.create_request_validator(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-behav-rv-"),
        validateRequestBody=True,
        validateRequestParameters=False,
    )
    ag.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        authorizationType="NONE",
        requestValidatorId=validator["id"],
        requestModels={"application/json": model_name},
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200"
    )
    ag.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "ok"}'},
    )

    # Positive control: a schema-valid body passes validation and reaches the MOCK integration, so a
    # target answering 400 to every call cannot pass the negative below.
    valid_resp = ag.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        pathWithQueryString="/widgets",
        body=json.dumps({"name": "widget"}),
    )
    assert valid_resp["status"] == 200, (
        f"expected a 200 response from TestInvokeMethod for a body conforming to the "
        f"attached RequestValidator's JSON-schema model, got {valid_resp.get('status')!r}: "
        f"{valid_resp.get('body')!r}"
    )
    assert valid_resp["body"] == '{"message": "ok"}', (
        f"expected the MOCK integration's rendered response body, got {valid_resp['body']!r}"
    )

    resp = ag.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        pathWithQueryString="/widgets",
        body=json.dumps({"unexpected-field-not-name": "value"}),
    )
    assert resp["status"] == 400, (
        f"expected a 400 response from TestInvokeMethod for a body violating the attached "
        f"RequestValidator's JSON-schema model, got {resp.get('status')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
