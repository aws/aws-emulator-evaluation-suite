"""update-model-invalid-schema-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-model-invalid-schema-rejected"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateModel on a WebSocket API with a schema that is not valid JSON is refused and leaves
    the stored schema untouched; the same model accepts a valid schema update afterward.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"), ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action", Tags=TAGS,
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    original_schema = json.dumps({
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": "Order", "type": "object",
        "properties": {"id": {"type": "string"}}, "required": ["id"],
    })
    model_id = agw.create_model(
        ApiId=api_id, Name="Order", ContentType="application/json", Schema=original_schema
    )["ModelId"]

    code, message = _error(lambda: agw.update_model(
        ApiId=api_id, ModelId=model_id, Schema="{not json"
    ))
    assert code == "BadRequestException", (
        f"UpdateModel with a malformed schema: expected BadRequestException, got {code}: {message!r}"
    )
    assert message == (
        "Invalid model specified: Validation Result: warnings : [], errors : [Invalid model schema "
        "specified]"
    ), f"unexpected message {message!r}"

    unchanged = agw.get_model(ApiId=api_id, ModelId=model_id)
    assert unchanged.get("Schema") == original_schema, (
        f"the refused UpdateModel must leave the stored schema untouched: {unchanged.get('Schema')!r}"
    )

    new_schema = json.dumps({
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": "Order", "type": "object",
        "properties": {"id": {"type": "string"}, "quantity": {"type": "integer"}},
        "required": ["id"],
    })
    updated = agw.update_model(ApiId=api_id, ModelId=model_id, Schema=new_schema)
    assert updated.get("Schema") == new_schema, (
        f"a valid schema update must apply: expected {new_schema!r}, got {updated.get('Schema')!r}"
    )
    confirmed = agw.get_model(ApiId=api_id, ModelId=model_id)
    assert confirmed.get("Schema") == new_schema, (
        f"independent read after a valid UpdateModel must show the new schema, "
        f"got {confirmed.get('Schema')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
