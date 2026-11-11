"""choice-comparators-are-type-strict-and-never-coerce-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "choice-comparators-are-type-strict-and-never-coerce-rejected"
GROUP = 'choice_state'
SERVICES = ['stepfunctions']


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
    """A permissionless execution role: Choice and Pass never assume it, but CreateStateMachine
    still requires a passable role ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-choice-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-choice: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "choice"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    # No API reports when a fresh role becomes passable; _create_state_machine retries
    # AccessDeniedException, and this sleep only makes that retry cheaper.
    time.sleep(2)
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
    """Start one execution, wait for a terminal status, return (describe, entered_state_names)."""
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
            break
        time.sleep(0.5)
    else:
        raise AssertionError(
            f"execution for input {input_data!r} never reached a terminal status within "
            f"{timeout_s}s; last describe was {desc!r}"
        )
    return desc, _entered_states(ctx, exec_arn)


def _entered_states(ctx, exec_arn):
    """Every state name the execution ENTERED, in order, from the paginated history."""
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
    return [
        e["stateEnteredEventDetails"]["name"]
        for e in events
        if "stateEnteredEventDetails" in e
    ]


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Choice comparator matches only its own JSON type (no "10" == 10, no 1 == true), and a type
    mismatch is a silent non-match: the execution falls through to Default and still SUCCEEDS.
    """
    role_arn = _execution_role(ctx)

    def machine(comparator, operand):
        return _create_state_machine(
            ctx,
            {
                "StartAt": "Route",
                "States": {
                    "Route": {
                        "Type": "Choice",
                        "Choices": [
                            {"Variable": "$.v", comparator: operand, "Next": "Matched"},
                        ],
                        "Default": "Fallback",
                    },
                    "Matched": {"Type": "Pass", "Result": "matched", "End": True},
                    "Fallback": {"Type": "Pass", "Result": "fell-back", "End": True},
                },
            },
            role_arn,
        )

    cases = [
        # (comparator, operand, matching value, non-matching values of other JSON types)
        ("NumericEquals", 10, 10, ["10", True, None, {"a": 1}, [10]]),
        ("StringEquals", "10", "10", [10, 10.0, True, None, {"a": "10"}]),
        ("BooleanEquals", True, True, ["true", "True", 1, None, {"a": True}]),
    ]

    for comparator, operand, matching, mismatched in cases:
        sm_arn = machine(comparator, operand)

        # Positive control, same machine: the correctly typed value takes the rule's branch.
        desc, entered = _run_execution(ctx, sm_arn, {"v": matching})
        assert desc["status"] == "SUCCEEDED", (
            f"{comparator}:{operand!r} control on the correctly typed value {matching!r} must "
            f"succeed, got status={desc.get('status')} error={desc.get('error')!r} "
            f"cause={desc.get('cause')!r}"
        )
        assert _output(desc) == "matched", (
            f"{comparator}:{operand!r} must match the same-typed value {matching!r}; expected "
            f"output 'matched', got {_output(desc)!r}"
        )
        assert entered == ["Route", "Matched"], (
            f"{comparator}:{operand!r} on {matching!r} must enter the rule's target; the history "
            f"entered {entered!r}, expected ['Route', 'Matched']"
        )

        for value in mismatched:
            # Only the JSON type of $.v differs from the control above.
            desc, entered = _run_execution(ctx, sm_arn, {"v": value})

            assert _output(desc) == "fell-back", (
                f"{comparator}:{operand!r} must NOT match the differently typed value "
                f"{value!r} (type {type(value).__name__}); expected the Default output "
                f"'fell-back', got {_output(desc)!r} -- a match here means the comparator "
                f"coerced across JSON types"
            )
            assert entered == ["Route", "Fallback"], (
                f"{comparator}:{operand!r} on {value!r} must never enter 'Matched'; the history "
                f"entered {entered!r}, expected ['Route', 'Fallback']"
            )

            # A type mismatch is a silent non-match, not an execution failure.
            assert desc["status"] == "SUCCEEDED", (
                f"a type mismatch must evaluate the rule to false and fall through to Default, "
                f"not fail the execution; {comparator}:{operand!r} on {value!r} gave "
                f"status={desc.get('status')} error={desc.get('error')!r} "
                f"cause={desc.get('cause')!r}"
            )
            assert desc.get("error") is None, (
                f"a type-mismatched Choice comparison must carry no error; "
                f"{comparator}:{operand!r} on {value!r} reported error={desc.get('error')!r} "
                f"cause={desc.get('cause')!r}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
