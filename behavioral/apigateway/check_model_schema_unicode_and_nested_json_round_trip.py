"""model-schema-unicode-and-nested-json-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "model-schema-unicode-and-nested-json-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A model schema with unicode characters and deep nesting survives CreateModel/GetModel unchanged."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-model-"),
        tags={"sim2real": "model-schema-unicode-and-nested-json-round-trip"},
    )
    rest_api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    schema_obj = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": "cafe-menu",
        "type": "object",
        "properties": {
            "名前": {
                "type": "string",
                "description": "商品名 - unicode field café",
            },
            "nested": {
                "type": "object",
                "properties": {
                    "items": {"type": "array", "items": {"type": "string"}},
                    "emoji": {"type": "string", "description": "\U0001F389 celebration"},
                    "escaped": {"type": "string", "description": "quote\" backslash\\ tab\\t"},
                },
            },
        },
        "required": ["名前"],
    }
    schema_json = json.dumps(schema_obj, ensure_ascii=False)

    apigw.create_model(
        restApiId=rest_api_id,
        name="CafeModel",
        contentType="application/json",
        schema=schema_json,
    )

    fetched = apigw.get_model(restApiId=rest_api_id, modelName="CafeModel")
    returned_schema = json.loads(fetched["schema"])

    assert returned_schema == schema_obj, (
        f"model schema changed on round-trip: {returned_schema!r} != {schema_obj!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
