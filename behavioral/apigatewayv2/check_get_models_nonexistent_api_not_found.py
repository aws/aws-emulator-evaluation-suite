"""get-models-nonexistent-api-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-models-nonexistent-api-not-found"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetModels against an ApiId that does not exist fails NotFoundException, while the same
    call lists a real API's own model."""
    agw = ctx.client("apigatewayv2")

    real_id = agw.create_api(
        Name=ctx.unique_name("sim2real-ws-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=TAGS,
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=real_id))

    bogus_id = "bogus-" + real_id
    code, message = _error(lambda: agw.get_models(ApiId=bogus_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent ApiId, got {code}: {message!r}"
    )
    assert message == f"Invalid API identifier specified {ctx.account}:{bogus_id}", (
        f"expected the exact invalid-API-identifier message for {bogus_id}, got {message!r}"
    )

    # Positive control: the same operation lists a real API's own model, so the rejection
    # above is about THIS id, not about GetModels being universally denied.
    schema = json.dumps({
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": "Sim2RealOrder",
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
    })
    model_id = agw.create_model(
        ApiId=real_id, Name="Sim2RealOrder", ContentType="application/json", Schema=schema
    )["ModelId"]

    items = agw.get_models(ApiId=real_id).get("Items", [])
    assert any(item["ModelId"] == model_id for item in items), (
        f"expected model {model_id!r} in GetModels for {real_id!r}, got "
        f"{[i['ModelId'] for i in items]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
