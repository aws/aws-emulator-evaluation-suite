"""get-model-template-generates-example-json."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-model-template-generates-example-json"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetModelTemplate server-side-generates a sample JSON payload whose fields match the model's schema."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-modeltmpl-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    schema = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": "ExampleModel",
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "count": {"type": "integer"},
                "active": {"type": "boolean"},
            },
            "required": ["id", "count"],
        }
    )
    apigw.create_model(
        restApiId=api_id, name="ExampleModel", contentType="application/json", schema=schema
    )

    resp = apigw.get_model_template(restApiId=api_id, modelName="ExampleModel")
    parsed = _poll_parsed_template(apigw, api_id, "ExampleModel", first_response=resp)

    assert set(["id", "count", "active"]).issubset(parsed.keys()), (
        f"template missing schema properties: {parsed.keys()}"
    )
    assert isinstance(parsed["id"], str), f"expected 'id' to render as a string, got: {parsed['id']!r}"
    assert isinstance(parsed["count"], int) and not isinstance(parsed["count"], bool), (
        f"expected 'count' to render as an integer, got: {parsed['count']!r}"
    )
    assert isinstance(parsed["active"], bool), (
        f"expected 'active' to render as a boolean, got: {parsed['active']!r}"
    )


def _strip_to_json(value):
    """GetModelTemplate renders a Velocity (VTL) mapping template, not a bare JSON document: it
    prefixes the JSON example body with directive lines such as "#set($inputRoot = ...)". Strip
    any leading '#'-directive lines before parsing the remaining body as JSON."""
    lines = [line for line in value.splitlines() if not line.lstrip().startswith("#")]
    return json.loads("\n".join(lines))


def _poll_parsed_template(apigw, api_id, model_name, first_response, timeout_s=60, interval_s=3):
    """GetModelTemplate can transiently return an empty body right after CreateModel while the
    model definition propagates; poll (bounded) until it renders a parseable JSON example."""
    deadline = time.monotonic() + timeout_s
    resp = first_response
    last_value = resp.get("value")
    while True:
        if last_value:
            try:
                return _strip_to_json(last_value)
            except json.JSONDecodeError:
                pass
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"get_model_template never returned a parseable JSON body (last value={last_value!r})"
            )
        time.sleep(interval_s)
        resp = apigw.get_model_template(restApiId=api_id, modelName=model_name)
        last_value = resp.get("value")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
