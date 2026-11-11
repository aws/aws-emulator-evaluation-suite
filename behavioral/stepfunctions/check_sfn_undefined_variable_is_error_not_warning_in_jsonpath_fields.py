"""sfn-undefined-variable-is-error-not-warning-in-jsonpath-fields."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "sfn-undefined-variable-is-error-not-warning-in-jsonpath-fields"
GROUP = "variables"
SERVICES = ["stepfunctions"]

_TASK_PARAMETERS = {"FunctionName": "dummy", "Payload": {"key.$": "$payloadVar"}}

_SHARED_STATES = {
    "WaitState": {
        "Type": "Wait",
        "SecondsPath": "$waitSeconds",
        "Next": "ChoiceState",
    },
    "ChoiceState": {
        "Type": "Choice",
        "Choices": [
            {"Variable": "$routeVar", "StringEquals": "go", "Next": "MapState"},
            {
                "Variable": "$.always_true_marker",
                "TimestampEqualsPath": "$tsVar",
                "Next": "MapState",
            },
        ],
        "Default": "MapState",
    },
    "MapState": {
        "Type": "Map",
        "ItemsPath": "$itemsVar",
        "ItemProcessor": {
            "StartAt": "Inner",
            "States": {"Inner": {"Type": "Pass", "End": True}},
        },
        "Next": "TaskState",
    },
    "TaskState": {
        "Type": "Task",
        "Resource": "arn:aws:states:::lambda:invoke",
        "InputPath": "$taskInput",
        "OutputPath": "$taskOutput",
        "Parameters": _TASK_PARAMETERS,
        "Next": "FailState",
    },
    "FailState": {
        "Type": "Fail",
        "ErrorPath": "$errVar",
        "CausePath": "$causeVar",
    },
}

# One undefined-variable reference per JSONPath-accepting field family: SecondsPath (Wait),
# Variable (Choice), an ...Path comparator (Choice), ItemsPath (Map), InputPath/OutputPath and a
# payload-template "key.$" (Task), ErrorPath/CausePath (Fail).
_EXPECTED_UNDEFINED = {
    ("waitSeconds", "SecondsPath", "/States/WaitState"),
    ("routeVar", "Variable", "/States/ChoiceState/Choices[0]"),
    ("tsVar", "TimestampEqualsPath", "/States/ChoiceState/Choices[1]"),
    ("itemsVar", "ItemsPath", "/States/MapState"),
    ("taskInput", "InputPath", "/States/TaskState"),
    ("payloadVar", "key.$", "/States/TaskState/Parameters/Payload"),
    ("taskOutput", "OutputPath", "/States/TaskState"),
    ("errVar", "ErrorPath", "/States/FailState"),
    ("causeVar", "CausePath", "/States/FailState"),
}


def _undefined_variable_tuples(diagnostics):
    out = set()
    for d in diagnostics:
        if d.get("code") != "UNDEFINED_VARIABLE":
            continue
        message = d["message"]
        prefix, suffix = "Variable '", "' referenced in the field '"
        assert message.startswith(prefix) and suffix in message, (
            f"UNDEFINED_VARIABLE message has an unexpected shape: {message!r}"
        )
        name = message[len(prefix):message.index(suffix)]
        field = message[message.index(suffix) + len(suffix):message.rindex("'")]
        out.add((name, field, d["location"]))
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """In a JSONPath state machine, an undefined variable reference is an ERROR-severity
    UNDEFINED_VARIABLE diagnostic that fails validation outright, in every JSONPath field family
    that accepts one -- unlike JSONata, where the same gap is only a WARNING and still reports OK.
    """
    sfn = ctx.client("stepfunctions")

    bad_definition = json.dumps({"StartAt": "WaitState", "States": _SHARED_STATES})
    bad = sfn.validate_state_machine_definition(definition=bad_definition)
    assert bad["result"] == "FAIL", f"expected FAIL for undefined variables, got {bad['result']!r}"
    assert bad["truncated"] is False, f"expected no truncation, got {bad['truncated']!r}"

    found = _undefined_variable_tuples(bad["diagnostics"])
    assert found == _EXPECTED_UNDEFINED, (
        f"UNDEFINED_VARIABLE diagnostics did not match the expected field set.\n"
        f"missing: {_EXPECTED_UNDEFINED - found}\nextra: {found - _EXPECTED_UNDEFINED}\n"
        f"full response: {bad['diagnostics']!r}"
    )
    for d in bad["diagnostics"]:
        assert d["severity"] == "ERROR", f"expected ERROR severity, got {d!r}"

    # Positive control: the identical state machine shape, with every referenced variable
    # properly Assigned up front, validates clean -- the FAIL above is about undefinedness,
    # not the shape of the definition.
    good_states = dict(_SHARED_STATES)
    good_states["Seed"] = {
        "Type": "Pass",
        "Assign": {
            "waitSeconds": 1,
            "routeVar": "go",
            "tsVar": "2024-01-01T00:00:00Z",
            "itemsVar": [1, 2],
            "taskInput": {"a": 1},
            "taskOutput": {"b": 2},
            "payloadVar": "hi",
            "errVar": "BoomError",
            "causeVar": "boom cause",
        },
        "Next": "WaitState",
    }
    good_definition = json.dumps({"StartAt": "Seed", "States": good_states})
    good = sfn.validate_state_machine_definition(definition=good_definition)
    assert good["result"] == "OK", f"expected OK once every variable is Assigned, got {good!r}"
    assert good["diagnostics"] == [], f"expected no diagnostics, got {good['diagnostics']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
