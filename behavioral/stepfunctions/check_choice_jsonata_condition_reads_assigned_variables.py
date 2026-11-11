"""choice-jsonata-condition-reads-assigned-variables."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "choice-jsonata-condition-reads-assigned-variables"
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
    # IAM propagation exposes no condition to poll; the bounded AccessDeniedException retry in
    # _create_state_machine is what makes this correct, and this sleep only makes it cheaper.
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


_CUTOFF = "2024-03-01T12:00:00Z"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A JSONata-mode Choice Condition reads a variable Assign-ed by an earlier state and calls
    $toMillis(): with n fixed at 9, a threshold of 5 routes to OverLimit and 50 to Default, and a
    timestamp past the cutoff routes to Late, each with the matching output and entered states."""
    role_arn = _execution_role(ctx)
    sm_arn = _create_state_machine(
        ctx,
        {
            "QueryLanguage": "JSONata",
            "StartAt": "Seed",
            "States": {
                # Assign lifts a value out of the input into a named state variable, so the
                # Choice below can only answer correctly by reading the variable store.
                "Seed": {
                    "Type": "Pass",
                    "Assign": {"threshold": "{% $states.input.limit %}"},
                    "Output": "{% $states.input %}",
                    "Next": "Route",
                },
                "Route": {
                    "Type": "Choice",
                    "Choices": [
                        {"Condition": "{% $states.input.n > $threshold %}", "Next": "OverLimit"},
                        {
                            "Condition": (
                                "{% $toMillis($states.input.when) > "
                                "$toMillis('" + _CUTOFF + "') %}"
                            ),
                            "Next": "Late",
                        },
                    ],
                    "Default": "Neither",
                },
                "OverLimit": {"Type": "Pass", "Output": "over-limit", "End": True},
                "Late": {"Type": "Pass", "Output": "late", "End": True},
                "Neither": {"Type": "Pass", "Output": "neither", "End": True},
            },
        },
        role_arn,
    )

    early = "2024-01-01T00:00:00Z"
    late = "2024-06-01T00:00:00Z"
    cases = [
        (
            {"n": 9, "limit": 5, "when": early},
            "over-limit",
            "OverLimit",
            "9 > the assigned threshold 5, so the variable-reading Condition must match",
        ),
        (
            {"n": 9, "limit": 50, "when": early},
            "neither",
            "Neither",
            "n is UNCHANGED at 9 and only the assigned threshold moved to 50, so the same "
            "Condition must now be false -- an implementation that ignores $threshold cannot "
            "give a different answer here than for the previous input. No Condition is "
            "satisfied, so this is also the Default case",
        ),
        (
            {"n": 9, "limit": 50, "when": late},
            "late",
            "Late",
            "the threshold rule stays false and only the timestamp moved past the cutoff, "
            "isolating the $toMillis() Condition",
        ),
    ]

    for input_data, expected_output, expected_state, why in cases:
        desc, entered = _run_execution(ctx, sm_arn, input_data)
        assert desc["status"] == "SUCCEEDED", (
            f"input {input_data!r} must succeed; every state is a Pass, so a failure here is the "
            f"JSONata evaluation erroring rather than routing. Got status={desc.get('status')} "
            f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        assert _output(desc) == expected_output, (
            f"input {input_data!r} produced output {_output(desc)!r}, expected "
            f"{expected_output!r} -- {why}"
        )
        assert entered == ["Seed", "Route", expected_state], (
            f"input {input_data!r} must enter ['Seed', 'Route', {expected_state!r}]; the history "
            f"entered {entered!r} -- {why}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
