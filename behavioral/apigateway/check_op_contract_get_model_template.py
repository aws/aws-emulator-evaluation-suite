"""op-contract-getModelTemplate."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-getModelTemplate"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetModelTemplate generates a VTL mapping template whose JSON example body's fields and
    types reflect the model's schema properties; a template request for a nonexistent model
    404s."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        tags={"sim2real": "get-model-template-generates-vtl-from-schema"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    model_name = "ExampleModel"
    schema = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": model_name,
            "type": "object",
            "properties": {"message": {"type": "string"}, "count": {"type": "integer"}},
        }
    )
    apigw.create_model(restApiId=api_id, name=model_name, contentType="application/json", schema=schema)

    value = apigw.get_model_template(restApiId=api_id, modelName=model_name)["value"]
    assert isinstance(value, str) and len(value) > 0, f"expected a non-empty template body, got {value!r}"
    parsed = _strip_vtl_directives_and_parse(value)
    assert isinstance(parsed, dict) and "message" in parsed and "count" in parsed, (
        f"expected the schema properties 'message' and 'count' in the generated JSON example, got {parsed!r}"
    )
    assert isinstance(parsed["message"], str), f"expected 'message' to render as a string, got {parsed['message']!r}"
    assert isinstance(parsed["count"], int) and not isinstance(parsed["count"], bool), (
        f"expected 'count' to render as an integer, got {parsed['count']!r}"
    )

    code, message = _error(lambda: apigw.get_model_template(restApiId=api_id, modelName="NoSuchModel"))
    assert code == "NotFoundException", f"expected NotFoundException for a nonexistent model, got {code}"
    assert message == "Invalid model name specified: NoSuchModel", f"unexpected message: {message!r}"


def _strip_vtl_directives_and_parse(value: str) -> Any:
    """GetModelTemplate renders a Velocity (VTL) mapping template, not a bare JSON document: it
    prefixes the JSON example body with directive lines such as "#set($inputRoot = ...)". Strip
    any leading '#'-directive lines before parsing the remaining body as JSON."""
    lines = [line for line in value.splitlines() if not line.lstrip().startswith("#")]
    return json.loads("\n".join(lines))


def _error(fn) -> Any:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
