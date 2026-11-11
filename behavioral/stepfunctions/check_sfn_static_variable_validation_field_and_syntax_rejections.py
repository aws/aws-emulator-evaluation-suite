"""sfn-static-variable-validation-field-and-syntax-rejections."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "sfn-static-variable-validation-field-and-syntax-rejections"
GROUP = "variables"
SERVICES = ["stepfunctions"]

_TASK_PARAMETERS = {"FunctionName": "dummy", "Payload": {}}


def _validate(sfn, states, start_at="TaskState"):
    return sfn.validate_state_machine_definition(
        definition=json.dumps({"StartAt": start_at, "States": states})
    )


def _only_diagnostic(resp):
    assert resp["result"] == "FAIL", f"expected FAIL, got {resp!r}"
    diags = resp["diagnostics"]
    assert len(diags) == 1, f"expected exactly one diagnostic, got {diags!r}"
    return diags[0]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Static validation of Variables/Assign rejects a per-state variable-count overrun, an
    unsupported 'Assign' on a Retrier, a variable in ResultPath, a non-literal TimestampEquals
    and a malformed intrinsic call, each with its own exact diagnostic and a clean counterpart.
    """
    sfn = ctx.client("stepfunctions")

    # VARIABLE_COUNT_LIMIT_EXCEEDED: 51 variables assigned in one state.
    over = _only_diagnostic(_validate(sfn, {
        "TaskState": {"Type": "Pass", "Assign": {f"v{i}": i for i in range(51)}, "End": True},
    }, start_at="TaskState"))
    assert over["code"] == "VARIABLE_COUNT_LIMIT_EXCEEDED", f"unexpected code: {over!r}"
    assert over["message"] == (
        "State 'TaskState' assigned 51 variables. A state can assign a maximum of 50 variables."
    ), f"unexpected message: {over['message']!r}"

    # Boundary: exactly 50 variables in one state validates clean.
    at_limit = _validate(sfn, {
        "TaskState": {"Type": "Pass", "Assign": {f"v{i}": i for i in range(50)}, "End": True},
    }, start_at="TaskState")
    assert at_limit["result"] == "OK", f"50 variables should be within the cap: {at_limit!r}"

    # Field 'Assign' is not supported on a Retrier.
    bad_retry = _only_diagnostic(_validate(sfn, {
        "TaskState": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": _TASK_PARAMETERS,
            "Retry": [{"ErrorEquals": ["States.ALL"], "Assign": {"x": 1}}],
            "End": True,
        },
    }))
    assert bad_retry["code"] == "SCHEMA_VALIDATION_FAILED", f"unexpected code: {bad_retry!r}"
    assert bad_retry["message"] == "Field 'Assign' is not supported", (
        f"unexpected message: {bad_retry['message']!r}"
    )
    assert bad_retry["location"] == "/States/TaskState/Retry[0]", (
        f"unexpected location: {bad_retry['location']!r}"
    )

    # A Retrier with no Assign validates clean -- the rejection above is about the field, not
    # about having a Retry block at all.
    good_retry = _validate(sfn, {
        "TaskState": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": _TASK_PARAMETERS,
            "Retry": [{"ErrorEquals": ["States.ALL"]}],
            "End": True,
        },
    })
    assert good_retry["result"] == "OK", f"Retry without Assign should validate clean: {good_retry!r}"

    # A variable reference in ResultPath is rejected: ResultPath is a raw reference path, and
    # the variable shorthand ('$name', no leading '.') is not a valid one there.
    bad_resultpath = _only_diagnostic(_validate(sfn, {
        "TaskState": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": _TASK_PARAMETERS,
            "Assign": {"myvar": 1},
            "ResultPath": "$myvar",
            "End": True,
        },
    }))
    assert bad_resultpath["code"] == "SCHEMA_VALIDATION_FAILED", f"unexpected code: {bad_resultpath!r}"
    assert bad_resultpath["message"] == "Value is not a Reference Path: Initial '$' must be followed by '.' or '['", (
        f"unexpected message: {bad_resultpath['message']!r}"
    )
    assert bad_resultpath["location"] == "/States/TaskState/ResultPath", (
        f"unexpected location: {bad_resultpath['location']!r}"
    )

    # The same ResultPath as an ordinary reference path (not a variable) validates clean.
    good_resultpath = _validate(sfn, {
        "TaskState": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": _TASK_PARAMETERS,
            "Assign": {"myvar": 1},
            "ResultPath": "$.result",
            "End": True,
        },
    })
    assert good_resultpath["result"] == "OK", f"a normal ResultPath should validate clean: {good_resultpath!r}"

    # TimestampEquals takes a literal RFC3339 timestamp, not a variable reference.
    bad_timestamp = _only_diagnostic(_validate(sfn, {
        "TaskState": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.ts", "TimestampEquals": "$myvar", "Next": "Done"}],
            "Default": "Done",
        },
        "Done": {"Type": "Pass", "End": True},
    }))
    assert bad_timestamp["code"] == "SCHEMA_VALIDATION_FAILED", f"unexpected code: {bad_timestamp!r}"
    assert bad_timestamp["message"] == "String does not match RFC3339 timestamp", (
        f"unexpected message: {bad_timestamp['message']!r}"
    )
    assert bad_timestamp["location"] == "/States/TaskState/Choices[0]/TimestampEquals", (
        f"unexpected location: {bad_timestamp['location']!r}"
    )

    # A literal timestamp in the same field validates clean.
    good_timestamp = _validate(sfn, {
        "TaskState": {
            "Type": "Choice",
            "Choices": [
                {"Variable": "$.ts", "TimestampEquals": "2024-01-01T00:00:00Z", "Next": "Done"}
            ],
            "Default": "Done",
        },
        "Done": {"Type": "Pass", "End": True},
    })
    assert good_timestamp["result"] == "OK", f"a literal timestamp should validate clean: {good_timestamp!r}"

    # A malformed intrinsic-function call (here: an unclosed States.Format(...)) is rejected.
    bad_format = _only_diagnostic(_validate(sfn, {
        "TaskState": {
            "Type": "Pass",
            "Parameters": {"msg.$": "States.Format('Hello {}'"},
            "End": True,
        },
    }))
    assert bad_format["code"] == "SCHEMA_VALIDATION_FAILED", f"unexpected code: {bad_format!r}"
    assert bad_format["message"] == (
        "The value for the field 'msg.$' must be a valid JSONPath or a valid intrinsic function call"
    ), f"unexpected message: {bad_format['message']!r}"
    assert bad_format["location"] == "/States/TaskState/Parameters", (
        f"unexpected location: {bad_format['location']!r}"
    )

    # The same call, well-formed, validates clean.
    good_format = _validate(sfn, {
        "TaskState": {
            "Type": "Pass",
            "Parameters": {"msg.$": "States.Format('Hello {}', $.name)"},
            "End": True,
        },
    })
    assert good_format["result"] == "OK", f"a well-formed States.Format should validate clean: {good_format!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
