"""update-model-schema."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-model-schema"
GROUP = "state-machine"
SERVICES = ["apigateway"]

_SCHEMA_V1 = json.dumps({
    "title": "Widget",
    "type": "object",
    "properties": {"id": {"type": "string"}},
    "required": ["id"],
})

_SCHEMA_V2 = json.dumps({
    "title": "Widget",
    "type": "object",
    "properties": {"id": {"type": "string"}, "color": {"type": "string"}},
    "required": ["id", "color"],
})


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Patching a model's schema mutates the stored JSON schema without changing modelId,
    visible in both GetModel and GetModels."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    model_name = "Widget" + ctx.unique_name("").replace("-", "")[:8]
    created = apigw.create_model(
        restApiId=api_id,
        name=model_name,
        contentType="application/json",
        schema=_SCHEMA_V1,
    )
    model_id_before = created["id"]
    assert json.loads(created["schema"]) == json.loads(_SCHEMA_V1), (
        f"expected freshly created model to echo schema v1, got {created['schema']!r}"
    )

    apigw.update_model(
        restApiId=api_id,
        modelName=model_name,
        patchOperations=[{"op": "replace", "path": "/schema", "value": _SCHEMA_V2}],
    )

    fetched = apigw.get_model(restApiId=api_id, modelName=model_name)
    assert fetched["id"] == model_id_before, (
        f"modelId must not change on schema patch: before={model_id_before!r} after={fetched['id']!r}"
    )
    fetched_schema = json.loads(fetched["schema"])
    assert fetched_schema == json.loads(_SCHEMA_V2), (
        f"GetModel must reflect the patched schema, got {fetched_schema!r}"
    )
    assert "color" in fetched_schema["properties"], (
        f"patched schema must include the new 'color' property, got {fetched_schema['properties']!r}"
    )

    listed = apigw.get_models(restApiId=api_id)["items"]
    match = next(m for m in listed if m["name"] == model_name)
    assert match["id"] == model_id_before, (
        f"GetModels must list the same modelId: expected={model_id_before!r} got={match['id']!r}"
    )
    listed_schema = json.loads(match["schema"])
    assert listed_schema == json.loads(_SCHEMA_V2), (
        f"GetModels listing must reflect the patched schema, got {listed_schema!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
