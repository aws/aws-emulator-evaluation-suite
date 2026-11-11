"""test-state-schema-validation-rejects-unsupported-fields."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-schema-validation-rejects-unsupported-fields"
GROUP = "state_machine_lifecycle"
SERVICES = ["stepfunctions"]


def _error(fn):
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message"))
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState rejects a Pass state carrying the Task-only field Resource with
    SCHEMA_VALIDATION_FAILED naming the field, and a state with no Type field at all with a
    distinct exact message; the same shape without the offending field succeeds."""
    sfn = ctx.client("stepfunctions")

    control = sfn.test_state(
        definition=json.dumps({"Type": "Pass", "Result": {"ok": True}, "End": True}), input="{}"
    )
    assert control["status"] == "SUCCEEDED", f"positive control did not succeed: {control!r}"

    pass_with_resource = json.dumps(
        {"Type": "Pass", "Resource": "arn:aws:lambda:us-west-2:123456789012:function:unused", "End": True}
    )
    code, message = _error(lambda: sfn.test_state(definition=pass_with_resource, input="{}"))
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code}: {message!r}"
    assert message == (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: Field 'Resource' is not "
        "supported at /States/StateName'"
    ), f"unexpected SCHEMA_VALIDATION_FAILED message: {message!r}"

    missing_type = json.dumps({"End": True})
    code, message = _error(lambda: sfn.test_state(definition=missing_type, input="{}"))
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code}: {message!r}"
    assert message == "Missing required field: 'Type'", f"unexpected missing-Type message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
