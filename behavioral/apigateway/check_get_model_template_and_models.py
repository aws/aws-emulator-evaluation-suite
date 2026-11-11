"""get-model-template-and-models."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-model-template-and-models"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetModelTemplate server-side-generates a sample document whose fields match a created
    model's JSON Schema, and GetModels lists that model alongside the built-in models."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-modeltmpl-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    model_name = "Sim2RealWidget"
    properties = {
        "message": {"type": "string"},
        "count": {"type": "number"},
    }
    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": model_name,
        "type": "object",
        "properties": properties,
    }
    apigw.create_model(
        restApiId=api_id,
        name=model_name,
        contentType="application/json",
        schema=json.dumps(schema),
    )

    parsed = _poll_parsed_template(apigw, api_id, model_name)
    assert set(properties).issubset(parsed.keys()), (
        f"expected schema properties {set(properties)} in generated template, got: {parsed.keys()}"
    )
    assert isinstance(parsed["message"], str), (
        f"expected 'message' sample to be a string per its schema type, got: {parsed['message']!r}"
    )
    assert isinstance(parsed["count"], (int, float)) and not isinstance(parsed["count"], bool), (
        f"expected 'count' sample to be numeric per its schema type, got: {parsed['count']!r}"
    )

    models = apigw.get_models(restApiId=api_id)["items"]
    names = {m["name"] for m in models}
    assert model_name in names, f"expected {model_name} in GetModels, got {names}"
    assert "Empty" in names and "Error" in names, (
        f"expected built-in models 'Empty' and 'Error' to still be present in GetModels, got {names}"
    )


def _strip_to_json(value):
    """GetModelTemplate renders a Velocity (VTL) mapping template, not a bare JSON document: it
    prefixes the JSON example body with directive lines such as "#set($inputRoot = ...)". Strip
    any leading '#'-directive lines before parsing the remaining body as JSON."""
    lines = [line for line in value.splitlines() if not line.lstrip().startswith("#")]
    return json.loads("\n".join(lines))


def _poll_parsed_template(apigw, api_id, model_name, timeout_s=60, interval_s=3):
    """GetModelTemplate can transiently return an empty body right after CreateModel while the
    model definition propagates; poll (bounded) until it renders a parseable JSON example."""
    deadline = time.monotonic() + timeout_s
    while True:
        value = apigw.get_model_template(restApiId=api_id, modelName=model_name).get("value")
        if value:
            try:
                return _strip_to_json(value)
            except json.JSONDecodeError:
                pass
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"get_model_template never returned a parseable JSON body (last value={value!r})"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
