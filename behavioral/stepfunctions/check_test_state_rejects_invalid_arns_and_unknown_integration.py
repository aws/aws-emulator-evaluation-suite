"""test-state-rejects-invalid-arns-and-unknown-integration."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-rejects-invalid-arns-and-unknown-integration"
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
    """TestState rejects a syntactically invalid roleArn, a Task Resource that is not an ARN at
    all, and an aws-sdk integration naming a service AWS does not recognize -- each with its own
    exact code and message; the same definitions with a real role and a real service succeed."""
    sfn = ctx.client("stepfunctions")

    pass_definition = json.dumps({"Type": "Pass", "Result": {"ok": True}, "End": True})
    control = sfn.test_state(definition=pass_definition, input="{}")
    assert control["status"] == "SUCCEEDED", f"positive control did not succeed: {control!r}"

    code, message = _error(lambda: sfn.test_state(definition=pass_definition, roleArn="invalid", input="{}"))
    assert code == "InvalidArn", f"expected InvalidArn, got {code}: {message!r}"
    assert message == "Invalid Role Arn: 'invalid'", f"unexpected InvalidArn message: {message!r}"

    not_an_arn = json.dumps({"Type": "Task", "Resource": "not-an-arn", "End": True})
    code, message = _error(lambda: sfn.test_state(definition=not_an_arn, input="{}"))
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code}: {message!r}"
    assert message == (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: Value is not a valid "
        "resource ARN at /States/StateName/Resource'"
    ), f"unexpected invalid-resource-ARN message: {message!r}"

    unknown_service = json.dumps(
        {
            "Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:bogusservice:someAction",
            "Parameters": {},
            "End": True,
        }
    )
    code, message = _error(lambda: sfn.test_state(definition=unknown_service, input="{}"))
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code}: {message!r}"
    assert message == (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: The resource provided "
        "arn:aws:states:::aws-sdk:bogusservice:someAction is not recognized. The value is not a "
        "valid resource ARN, or the resource is not available in this region. at "
        "/States/StateName/Resource'"
    ), f"unexpected unknown-aws-sdk-service message: {message!r}"

    # A recognized aws-sdk integration clears the ARN schema check above and fails only at a
    # later, unrelated validation stage -- proof the two rejections above are about the ARN
    # itself, not about this account or region.
    known_service = json.dumps(
        {
            "Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:sfn:listStateMachines",
            "Parameters": {},
            "End": True,
        }
    )
    code, message = _error(lambda: sfn.test_state(definition=known_service, input="{}"))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "RoleArn must be specified when testing a Task state", (
        f"unexpected ValidationException message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
