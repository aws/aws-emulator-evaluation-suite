"""create-blueprint-invalid-name-pattern-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-blueprint-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBlueprint with a blueprintName violating the ^[a-zA-Z0-9-_]+$ pattern (spaces/punctuation)
    is rejected server-side with ValidationException and creates nothing, while a validly-named
    Blueprint still creates successfully."""
    bda = ctx.client("bedrock-data-automation")

    invalid_name = "invalid blueprint name!"
    code, message = _client_error(
        lambda: bda.create_blueprint(blueprintName=invalid_name, type="DOCUMENT", schema=_blueprint_schema())
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message})"
    assert message == (
        "1 validation error detected: Value at 'blueprintName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9-_]+"
    ), f"unexpected message: {message!r}"

    # Positive control: a validly-patterned name still creates fine.
    valid_name = ctx.unique_name("sim2real-bp-valid-")
    arn = bda.create_blueprint(
        blueprintName=valid_name,
        type="DOCUMENT",
        schema=_blueprint_schema(),
        tags=[{"key": "sim2real", "value": "1"}],
    )["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))
    got_name = bda.get_blueprint(blueprintArn=arn)["blueprint"]["blueprintName"]
    assert got_name == valid_name, f"expected blueprintName {valid_name!r}, got {got_name!r}"


def _blueprint_schema(class_name: str = "SimparityTestDoc", field: str = "test_field") -> str:
    return json.dumps(
        {
            "class": class_name,
            "description": "Simparity behavioral fidelity test blueprint",
            "properties": {
                field: {
                    "type": "string",
                    "inferenceType": "explicit",
                    "instruction": "Extract the test field value",
                }
            },
        }
    )


def _client_error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
