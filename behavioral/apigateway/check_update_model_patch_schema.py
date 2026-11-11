"""update-model-patch-schema."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-model-patch-schema"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateModel patches only the schema field; name/contentType are untouched."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)

    model_name = "Widget" + ctx.unique_name("").replace("-", "")[:8]
    schema_v1 = json.dumps({"$schema": "http://json-schema.org/draft-04/schema#",
                             "title": "Widget", "type": "object",
                             "properties": {"id": {"type": "string"}}})
    created = apigw.create_model(
        restApiId=api_id,
        name=model_name,
        contentType="application/json",
        description="widget model",
        schema=schema_v1,
    )
    assert created["name"] == model_name, f"expected created model name {model_name!r}, got {created['name']!r}"
    assert created["contentType"] == "application/json", (
        f"expected created contentType 'application/json', got {created['contentType']!r}"
    )

    schema_v2 = json.dumps({"$schema": "http://json-schema.org/draft-04/schema#",
                             "title": "Widget", "type": "object",
                             "properties": {"id": {"type": "string"}, "price": {"type": "number"}}})
    updated = apigw.update_model(
        restApiId=api_id,
        modelName=model_name,
        patchOperations=[{"op": "replace", "path": "/schema", "value": schema_v2}],
    )
    assert updated["name"] == model_name, "UpdateModel must not change the model name"
    assert updated["contentType"] == "application/json", "UpdateModel must not change contentType"
    assert json.loads(updated["schema"]) == json.loads(schema_v2), (
        f"expected UpdateModel response schema {schema_v2}, got {updated['schema']}"
    )

    fetched = apigw.get_model(restApiId=api_id, modelName=model_name)
    assert fetched["name"] == model_name, f"expected fetched model name {model_name!r}, got {fetched['name']!r}"
    assert fetched["contentType"] == "application/json", (
        f"expected fetched contentType 'application/json', got {fetched['contentType']!r}"
    )
    assert json.loads(fetched["schema"]) == json.loads(schema_v2), "GetModel must reflect the patched schema"

    apigw.delete_model(restApiId=api_id, modelName=model_name)
    get_error = _client_error(lambda: apigw.get_model(restApiId=api_id, modelName=model_name))
    assert get_error.get("Code") == "NotFoundException", (
        f"expected GetModel on a deleted model to return NotFoundException, got {get_error}"
    )
    assert get_error.get("Message") == f"Invalid model name specified: {model_name}", (
        f"expected the exact NotFound message from GetModel on a deleted model, got {get_error.get('Message')!r}"
    )
    update_error = _client_error(lambda: apigw.update_model(
        restApiId=api_id,
        modelName=model_name,
        patchOperations=[{"op": "replace", "path": "/schema", "value": schema_v2}],
    ))
    assert update_error.get("Code") == "NotFoundException", (
        f"expected UpdateModel on a deleted model to return NotFoundException, got {update_error}"
    )
    assert update_error.get("Message") == f"Invalid model name specified: {model_name}", (
        f"expected the exact NotFound message from UpdateModel on a deleted model, "
        f"got {update_error.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_rest_api(ctx) -> str:
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(name=ctx.unique_name("sim2real-bh-api-"), tags={"sim2real": CHECK})
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
