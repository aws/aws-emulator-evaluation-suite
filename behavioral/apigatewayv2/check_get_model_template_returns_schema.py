"""get-model-template-returns-schema."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-model-template-returns-schema"
GROUP = "data-plane"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetModelTemplate returns a VTL template keying each schema property, quoted for a string type
    and a bare number for an integer type; a nonexistent ModelId fails NotFoundException."""
    apigw = ctx.client("apigatewayv2")

    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-ws-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-ws"},
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": "Sim2RealModel",
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "count": {"type": "integer"},
        },
        "required": ["id", "count"],
    }
    model = apigw.create_model(
        ApiId=api_id,
        Name="Sim2RealModel",
        ContentType="application/json",
        Schema=json.dumps(schema),
    )
    model_id = model["ModelId"]

    def _get_value():
        template = apigw.get_model_template(ApiId=api_id, ModelId=model_id)
        return template.get("Value") or ""

    value = _poll_until(_get_value, lambda v: v != "", timeout_s=30)

    # The template is a VTL mapping template (starts with a VTL directive),
    # not raw JSON — GetModelTemplate returns the generator's source, so we
    # assert on the schema-derived content rather than parsing it as JSON.
    assert "#set" in value or "$input" in value, (
        f"expected a VTL mapping template body, got: {value!r}"
    )
    assert '"id"' in value, f"template missing the 'id' property key: {value!r}"
    assert '"count"' in value, f"template missing the 'count' property key: {value!r}"

    # A string-typed property is templated as a quoted placeholder value; an
    # integer-typed property is templated as a bare (unquoted) number.
    id_line = next(line for line in value.splitlines() if '"id"' in line)
    count_line = next(line for line in value.splitlines() if '"count"' in line)
    assert ":" in id_line and '"' in id_line.split(":", 1)[1], (
        f"'id' (string) should be templated with a quoted value: {id_line!r}"
    )
    count_value_part = count_line.split(":", 1)[1].strip().rstrip(",")
    assert not count_value_part.startswith('"'), (
        f"'count' (integer) should be templated as a bare number, not quoted: {count_line!r}"
    )

    missing_model_id = "aaaaaaaaaa"
    missing_code, missing_message = _error(
        lambda: apigw.get_model_template(ApiId=api_id, ModelId=missing_model_id)
    )
    assert missing_code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent ModelId, got {missing_code!r}: {missing_message!r}"
    )
    assert missing_message == f"Invalid model identifier specified: {missing_model_id}", (
        f"expected the exact invalid-model-identifier message, got {missing_message!r}"
    )


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


