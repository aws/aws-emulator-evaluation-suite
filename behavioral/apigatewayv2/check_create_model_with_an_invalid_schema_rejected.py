"""create-model-with-an-invalid-schema-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-with-an-invalid-schema-rejected"
GROUP = "models"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModel on a WebSocket API with a schema that is not valid JSON is refused and no model
    is created; the same name with a valid JSON schema is created and reads back byte-identical.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"), ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action", Tags=TAGS,
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    code, message = _error(lambda: agw.create_model(
        ApiId=api_id, Name="Order", ContentType="application/json", Schema="{not json"
    ))
    assert code == "BadRequestException", (
        f"CreateModel with a malformed schema: expected BadRequestException, got {code}: {message!r}"
    )
    assert message == (
        "Invalid model specified: Validation Result: warnings : [], errors : [Invalid model schema "
        "specified]"
    ), f"unexpected message {message!r}"
    names = [m["Name"] for m in agw.get_models(ApiId=api_id).get("Items", [])]
    assert names == [], f"the refused CreateModel left models behind: {names!r}"

    schema = json.dumps({
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": "Order", "type": "object",
        "properties": {"id": {"type": "string"}}, "required": ["id"],
    })
    model_id = agw.create_model(
        ApiId=api_id, Name="Order", ContentType="application/json", Schema=schema
    )["ModelId"]
    stored = agw.get_model(ApiId=api_id, ModelId=model_id)
    assert stored.get("Schema") == schema, f"the stored schema differs: {stored.get('Schema')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

