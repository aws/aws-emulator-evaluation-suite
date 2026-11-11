"""update-model-and-validator-in-place."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-model-and-validator-in-place"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateModel patches schema/description and UpdateRequestValidator patches its flags, preserving ids."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-model-")
    rest_api_id = apigw.create_rest_api(name=name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))

    schema_v1 = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": "Widget",
            "type": "object",
            "properties": {"id": {"type": "string"}},
        }
    )
    created_model = apigw.create_model(
        restApiId=rest_api_id, name="Widget", contentType="application/json", schema=schema_v1, description="v1"
    )
    model_id = created_model["id"]

    schema_v2 = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": "Widget",
            "type": "object",
            "properties": {"id": {"type": "string"}, "count": {"type": "integer"}},
        }
    )
    apigw.update_model(
        restApiId=rest_api_id,
        modelName="Widget",
        patchOperations=[
            {"op": "replace", "path": "/description", "value": "v2"},
            {"op": "replace", "path": "/schema", "value": schema_v2},
        ],
    )
    after_model = apigw.get_model(restApiId=rest_api_id, modelName="Widget")
    assert after_model["id"] == model_id, "the model id must be preserved across an in-place update"
    assert after_model["description"] == "v2", f"expected description 'v2', got {after_model['description']!r}"
    after_model_props = json.loads(after_model["schema"])["properties"]
    assert "count" in after_model_props, f"expected patched schema to add 'count', got properties {list(after_model_props)}"

    created_validator = apigw.create_request_validator(
        restApiId=rest_api_id, name="v1-validator", validateRequestBody=True, validateRequestParameters=False
    )
    validator_id = created_validator["id"]

    apigw.update_request_validator(
        restApiId=rest_api_id,
        requestValidatorId=validator_id,
        patchOperations=[
            {"op": "replace", "path": "/validateRequestBody", "value": "false"},
            {"op": "replace", "path": "/validateRequestParameters", "value": "true"},
        ],
    )
    after_validator = apigw.get_request_validator(restApiId=rest_api_id, requestValidatorId=validator_id)
    assert after_validator["id"] == validator_id, "the validator id must be preserved across an in-place update"
    assert after_validator["validateRequestBody"] is False, (
        f"expected validateRequestBody False, got {after_validator['validateRequestBody']!r}"
    )
    assert after_validator["validateRequestParameters"] is True, (
        f"expected validateRequestParameters True, got {after_validator['validateRequestParameters']!r}"
    )


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
