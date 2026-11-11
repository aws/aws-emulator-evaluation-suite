"""choice-timestamp-comparators-compare-instants-not-lexical-strings."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "choice-timestamp-comparators-compare-instants-not-lexical-strings"
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


# The cutoff every rule below is written against. 12:00 UTC is chosen so that an offset form of
# the SAME instant sorts on the WRONG side of it as a plain string.
_CUTOFF = "2024-03-01T12:00:00Z"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Timestamp* comparators compare RFC3339 values as instants, so a UTC-offset form routes by the
    moment it denotes, not its string order; an unparseable value matches none and takes Default.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/state-choice.html
    """
    role_arn = _execution_role(ctx)
    sm_arn = _create_state_machine(
        ctx,
        {
            "StartAt": "Route",
            "States": {
                "Route": {
                    "Type": "Choice",
                    "Choices": [
                        {"Variable": "$.when", "TimestampGreaterThan": _CUTOFF, "Next": "After"},
                        {"Variable": "$.when", "TimestampEquals": _CUTOFF, "Next": "Same"},
                        {"Variable": "$.when", "TimestampLessThan": _CUTOFF, "Next": "Before"},
                    ],
                    "Default": "Unparsed",
                },
                "After": {"Type": "Pass", "Result": "after", "End": True},
                "Same": {"Type": "Pass", "Result": "same", "End": True},
                "Before": {"Type": "Pass", "Result": "before", "End": True},
                "Unparsed": {"Type": "Pass", "Result": "unparsed", "End": True},
            },
        },
        role_arn,
    )

    cases = [
        # (input, expected output, expected target state, why this input is here)
        (
            "2024-03-01T13:00:00Z",
            "after",
            "After",
            "an hour past the cutoff in plain UTC: the baseline both orders agree on",
        ),
        (
            "2024-03-01T12:00:00Z",
            "same",
            "Same",
            "byte-identical to the cutoff, so TimestampEquals must match and "
            "TimestampGreaterThan must not",
        ),
        (
            "2024-03-01T11:00:00Z",
            "before",
            "Before",
            "an hour before the cutoff in plain UTC",
        ),
        (
            "2024-03-01T13:00:00+01:00",
            "same",
            "Same",
            "THE SAME INSTANT as the 12:00Z cutoff expressed at +01:00; it sorts AFTER the "
            "cutoff as a string, so a lexical comparison wrongly takes TimestampGreaterThan",
        ),
        (
            "2024-03-01T08:00:00-05:00",
            "after",
            "After",
            "13:00Z, an hour AFTER the cutoff, expressed at -05:00; it sorts BEFORE the cutoff "
            "as a string, so a lexical comparison wrongly takes TimestampLessThan",
        ),
        (
            "not-a-timestamp",
            "unparsed",
            "Unparsed",
            "not an RFC3339 value at all, so it can satisfy no timestamp comparator",
        ),
        (
            "2024-03-01",
            "unparsed",
            "Unparsed",
            "a bare date is not a full RFC3339 timestamp, so it matches nothing -- an "
            "implementation that date-pads it would route to Before",
        ),
    ]

    for when, expected_output, expected_state, why in cases:
        desc, entered = _run_execution(ctx, sm_arn, {"when": when})
        assert desc["status"] == "SUCCEEDED", (
            f"input when={when!r} must succeed; every branch and the Default are Pass states, so "
            f"a failure here is the comparator erroring rather than evaluating. Got "
            f"status={desc.get('status')} error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        assert desc.get("error") is None, (
            f"input when={when!r} must carry no error, got error={desc.get('error')!r} "
            f"cause={desc.get('cause')!r}"
        )
        assert _output(desc) == expected_output, (
            f"when={when!r} routed to output {_output(desc)!r}, expected "
            f"{expected_output!r} -- {why}"
        )
        assert entered == ["Route", expected_state], (
            f"when={when!r} must enter exactly ['Route', {expected_state!r}]; the execution "
            f"history entered {entered!r} -- {why}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
