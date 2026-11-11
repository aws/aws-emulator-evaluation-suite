"""get-model-template-generates-example-payload."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-model-template-generates-example-payload"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetModelTemplate returns a server-generated example payload whose keys AND value
    types reflect the model's actual stored JSON schema, not a generic stub."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-model-api-"),
        tags={"sim2real": "get-model-template-generates-example-payload"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    model_name = "SimparityWidget"
    schema = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": model_name,
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "count": {"type": "integer"},
            },
            "required": ["id"],
        }
    )
    apigw.create_model(restApiId=api_id, name=model_name, contentType="application/json", schema=schema)
    ctx.on_cleanup(lambda: apigw.delete_model(restApiId=api_id, modelName=model_name))

    parsed = _poll_parsed_template(apigw, api_id, model_name)
    assert "id" in parsed, f"expected schema property 'id' reflected in template, got: {parsed}"
    assert "count" in parsed, f"expected schema property 'count' reflected in template, got: {parsed}"
    assert isinstance(parsed["id"], str), (
        f"expected 'id' rendered as a string-typed example (schema says string), got: {parsed['id']!r}"
    )
    assert isinstance(parsed["count"], int) and not isinstance(parsed["count"], bool), (
        f"expected 'count' rendered as an integer-typed example (schema says integer), got: {parsed['count']!r}"
    )

    models = apigw.get_models(restApiId=api_id)["items"]
    assert any(m["name"] == model_name for m in models), models

    # A model with a schema field the server cannot render a template for should still be a
    # sane, retrievable model (schema round-trips through GetModel) even before templating.
    got = apigw.get_model(restApiId=api_id, modelName=model_name)
    assert json.loads(got["schema"])["title"] == model_name


def _strip_to_json(value: str) -> dict:
    """GetModelTemplate renders a Velocity (VTL) mapping template, not bare JSON: it can
    prefix the example body with directive lines such as '#set($inputRoot = ...)'. Strip any
    leading '#'-directive lines before parsing the remainder as JSON."""
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
