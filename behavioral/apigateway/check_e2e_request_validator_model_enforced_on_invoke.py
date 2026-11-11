"""e2e-request-validator-model-enforced-on-invoke."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "e2e-request-validator-model-enforced-on-invoke"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A method wired to a request validator + JSON schema model rejects an invalid request
    body at invocation time (400) and accepts a schema-valid body end-to-end (200)."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        tags={"sim2real": "request-validator-model-enforced"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    model_name = "ItemInput"
    schema = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": model_name,
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }
    )
    apigw.create_model(
        restApiId=api_id,
        name=model_name,
        contentType="application/json",
        schema=schema,
    )

    validator_id = apigw.create_request_validator(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-behav-validator-"),
        validateRequestBody=True,
        validateRequestParameters=False,
    )["id"]

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        authorizationType="NONE",
        requestValidatorId=validator_id,
        requestModels={"application/json": model_name},
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "accepted"}'},
    )

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    apigw.create_stage(restApiId=api_id, stageName="teststage", deploymentId=deployment_id)

    # Missing the required "name" property -> validator rejects before the integration runs.
    invalid_invoke = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        body=json.dumps({"unexpected": "field"}),
    )
    assert invalid_invoke["status"] == 400, (
        f"expected 400 for schema-invalid body, got {invalid_invoke['status']}: "
        f"{invalid_invoke.get('body')}"
    )
    assert invalid_invoke["body"] == '{"message": "Invalid request body"}', (
        f"expected the validator's specific rejection body, got {invalid_invoke.get('body')}"
    )

    # Schema-valid body -> passes validation and reaches the MOCK integration.
    valid_invoke = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        body=json.dumps({"name": "widget"}),
    )
    assert valid_invoke["status"] == 200, (
        f"expected 200 for schema-valid body, got {valid_invoke['status']}: "
        f"{valid_invoke.get('body')}"
    )
    assert valid_invoke["body"] == '{"message": "accepted"}', valid_invoke["body"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
