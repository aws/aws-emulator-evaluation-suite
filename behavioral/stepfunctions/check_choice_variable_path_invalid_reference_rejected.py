"""choice-variable-path-invalid-reference-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-variable-path-invalid-reference-rejected"
GROUP = "choice_state"
SERVICES = ["stepfunctions"]


_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _execution_role(ctx):
    """A throwaway execution role, so the check assumes no pre-existing estate."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-choice-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-choice: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "choice"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-choice-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "choice"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_execution(ctx, sm_arn, input_data, *, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-choice-ex-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            return desc, _history_events(ctx, exec_arn)
        time.sleep(0.5)
    raise AssertionError(
        f"execution for input {input_data!r} never reached a terminal status within "
        f"{timeout_s}s; last describe was {desc!r}"
    )


def _history_events(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    token = None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            break
    return events


def _entered_states(events):
    return [
        e["stateEnteredEventDetails"]["name"] for e in events if "stateEnteredEventDetails" in e
    ]


def _state_entered_event_id(events, state_name: str) -> int:
    for e in events:
        details = e.get("stateEnteredEventDetails")
        if details and details["name"] == state_name:
            return e["id"]
    raise AssertionError(f"no StateEntered event for {state_name!r} in history {events!r}")


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


def _machine(*, variable, input_path=None):
    route = {
        "Type": "Choice",
        "Choices": [{"Variable": variable, "StringEquals": "x", "Next": "Matched"}],
        "Default": "Fallback",
    }
    if input_path is not None:
        route["InputPath"] = input_path
    return {
        "StartAt": "Route",
        "States": {
            "Route": route,
            "Matched": {"Type": "Pass", "Result": "matched", "End": True},
            "Fallback": {"Type": "Pass", "Result": "fell-back", "End": True},
        },
    }


_RUNTIME_ERROR = "States.Runtime"


def _invalid_path_cause(state_name: str, event_id: int, path: str) -> str:
    return (
        f"An error occurred while executing the state '{state_name}' (entered at the event "
        f"id #{event_id}). Invalid path '{path}': The choice state's condition path references "
        f"an invalid value."
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Choice Variable that does not resolve to a value -- absent under an InputPath, indexing
    a scalar, or indexing past an array's end -- fails States.Runtime with the exact cause AWS
    names the unresolvable path with, never falling through to Default.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-choice-state.html
    """
    role_arn = _execution_role(ctx)

    cases = [
        (
            "under an InputPath that rebases the Variable",
            _machine(variable="$.v", input_path="$.scope"),
            {"scope": {"other": 1}},
            "$.v",
            {"scope": {"other": 1, "v": "x"}},
        ),
        (
            "indexing a scalar",
            _machine(variable="$.condition[0]"),
            {"condition": "a-scalar-string"},
            "$.condition[0]",
            {"condition": ["x"]},
        ),
        (
            "indexing past the end of an array",
            _machine(variable="$.items[5]"),
            {"items": ["a", "b"]},
            "$.items[5]",
            {"items": ["a", "b", "c", "d", "e", "x"]},
        ),
    ]

    for why, definition, bad_input, variable_path, good_input in cases:
        sm_arn = _create_state_machine(ctx, definition, role_arn)

        # Positive control first: the very same machine resolves and routes on a valid value,
        # so the failure below is attributable to the unresolvable path, not to the machine.
        good_desc, good_events = _run_execution(ctx, sm_arn, good_input)
        good_entered = _entered_states(good_events)
        assert good_desc["status"] == "SUCCEEDED", (
            f"[{why}] control input {good_input!r} must succeed, got "
            f"status={good_desc.get('status')} error={good_desc.get('error')!r} "
            f"cause={good_desc.get('cause')!r}"
        )
        assert _output(good_desc) == "matched", (
            f"[{why}] control input {good_input!r} must route to 'Matched', got "
            f"{_output(good_desc)!r}"
        )
        assert good_entered == ["Route", "Matched"], (
            f"[{why}] control must enter ['Route', 'Matched'], history entered {good_entered!r}"
        )

        bad_desc, bad_events = _run_execution(ctx, sm_arn, bad_input)
        bad_entered = _entered_states(bad_events)
        assert bad_desc["status"] == "FAILED", (
            f"[{why}] input {bad_input!r} must fail the execution rather than evaluate false and "
            f"fall through to Default; got status={bad_desc.get('status')} "
            f"output={bad_desc.get('output')!r}"
        )
        assert bad_desc.get("error") == _RUNTIME_ERROR, (
            f"[{why}] expected error {_RUNTIME_ERROR!r}, got {bad_desc.get('error')!r} "
            f"(cause={bad_desc.get('cause')!r})"
        )
        route_event_id = _state_entered_event_id(bad_events, "Route")
        expected_cause = _invalid_path_cause("Route", route_event_id, variable_path)
        assert bad_desc.get("cause") == expected_cause, (
            f"[{why}] expected cause {expected_cause!r}, got {bad_desc.get('cause')!r}"
        )
        assert bad_desc.get("output") is None, (
            f"[{why}] a failed execution must carry no output, got {bad_desc.get('output')!r}"
        )
        assert bad_entered == ["Route"], (
            f"[{why}] an unresolvable Variable must enter the Choice and stop there -- neither "
            f"'Matched' nor 'Fallback' may be entered; history entered {bad_entered!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
