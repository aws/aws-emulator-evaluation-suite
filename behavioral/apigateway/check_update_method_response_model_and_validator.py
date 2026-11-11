"""update-method-response-model-and-validator."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-method-response-model-and-validator"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMethodResponse, UpdateModel, and UpdateRequestValidator JSON-Patch
    semantics persist changes visible on subsequent reads."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-updmrv-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseModels={"application/json": "Empty"},
    )

    model_name = "Sim2RealItem"
    apigw.create_model(
        restApiId=api_id,
        name=model_name,
        contentType="application/json",
        description="original description",
        schema=json.dumps({"title": model_name, "type": "object", "properties": {"id": {"type": "string"}}}),
    )

    # --- UpdateMethodResponse: swap the built-in Empty model for our custom one.
    apigw.update_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        patchOperations=[
            {"op": "replace", "path": "/responseModels/application~1json", "value": model_name}
        ],
    )
    method_response = apigw.get_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    assert method_response["responseModels"]["application/json"] == model_name, (
        f"expected responseModels['application/json'] == {model_name!r}, got {method_response['responseModels']!r}"
    )

    # --- UpdateModel: patch the description.
    apigw.update_model(
        restApiId=api_id,
        modelName=model_name,
        patchOperations=[{"op": "replace", "path": "/description", "value": "updated description"}],
    )
    model = apigw.get_model(restApiId=api_id, modelName=model_name)
    assert model["description"] == "updated description", (
        f"expected description == 'updated description', got {model['description']!r}"
    )

    # --- UpdateRequestValidator: patch validateRequestParameters.
    validator_id = apigw.create_request_validator(
        restApiId=api_id, name="sim2real-validator", validateRequestBody=True, validateRequestParameters=False
    )["id"]
    apigw.update_request_validator(
        restApiId=api_id,
        requestValidatorId=validator_id,
        patchOperations=[{"op": "replace", "path": "/validateRequestParameters", "value": "true"}],
    )
    validator = apigw.get_request_validator(restApiId=api_id, requestValidatorId=validator_id)
    assert validator["validateRequestParameters"] is True, (
        f"expected validateRequestParameters == True, got {validator['validateRequestParameters']!r}"
    )
    assert validator["validateRequestBody"] is True, (
        f"unrelated field must be unaffected by the patch: expected validateRequestBody == True, "
        f"got {validator['validateRequestBody']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
