"""array-get-item-negative-index-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "array-get-item-negative-index-rejected"
GROUP = "intrinsic_functions"
SERVICES = ["stepfunctions"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_sfn_role(ctx) -> str:
    """An execution role this check owns; a Choice/Pass machine calls no AWS service."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnarr-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_state_machine(ctx, definition, role_arn, name):
    """Create a STANDARD machine, retrying while the freshly created role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _run_to_terminal(ctx, sm_arn, exec_name, input_data, *, timeout_s=60.0):
    """Start one named execution and poll DescribeExecution every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_name, input=json.dumps(input_data)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """States.ArrayGetItem with a literal negative index fails the execution with
    States.Runtime naming the intrinsic call that could not be evaluated; the same
    intrinsic given a valid non-negative index succeeds.
    """
    role_arn = _create_sfn_role(ctx)
    sm_name = ctx.unique_name("sim2real-behav-sfnarr-")
    definition = {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.mode", "StringEquals": "bad", "Next": "BadGet"}],
                "Default": "GoodGet",
            },
            "GoodGet": {
                "Type": "Pass",
                "Parameters": {"item.$": "States.ArrayGetItem($.grades, 1)"},
                "End": True,
            },
            "BadGet": {
                "Type": "Pass",
                "Parameters": {"item.$": "States.ArrayGetItem($.grades, -1)"},
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn, sm_name)
    grades = [90, 80, 70]

    # --- Positive control: a valid non-negative index succeeds --------------------------
    good = _run_to_terminal(
        ctx, sm_arn, ctx.unique_name("sim2real-x-good-"), {"mode": "good", "grades": grades}
    )
    assert good["status"] == "SUCCEEDED", (
        f"the control ArrayGetItem(grades, 1) must succeed, got {good['status']!r} "
        f"error={good.get('error')!r} cause={good.get('cause')!r}"
    )
    assert json.loads(good["output"]) == {"item": grades[1]}, (
        f"ArrayGetItem(grades, 1) must return {grades[1]!r}, got {good.get('output')!r}"
    )

    # --- The subject: a literal negative index is an invalid argument -------------------
    bad = _run_to_terminal(
        ctx, sm_arn, ctx.unique_name("sim2real-x-bad-"), {"mode": "bad", "grades": grades}
    )
    assert bad["status"] == "FAILED", (
        f"ArrayGetItem(grades, -1) must fail the execution, got {bad['status']!r} "
        f"output={bad.get('output')!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"expected error 'States.Runtime', got {bad.get('error')!r} cause={bad.get('cause')!r}"
    )

    events = _history(ctx, bad["executionArn"])
    entered = [
        e for e in events
        if e["type"] == "PassStateEntered" and e["stateEnteredEventDetails"]["name"] == "BadGet"
    ]
    assert len(entered) == 1, (
        f"expected exactly one PassStateEntered(BadGet) event, got history types "
        f"{[e['type'] for e in events]!r}"
    )
    expected_cause = (
        f"An error occurred while executing the state 'BadGet' (entered at the event "
        f"id #{entered[0]['id']}). There was an error while evaluating the intrinsic "
        f"function: States.ArrayGetItem($.grades, -1). Invalid arguments in "
        f"States.ArrayGetItem"
    )
    assert bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {bad.get('cause')!r}"
    )
    assert bad.get("output") is None, f"a failed intrinsic produced output {bad.get('output')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
