"""deep-sfn-language-wait-seconds-path-invalid-value-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-wait-seconds-path-invalid-value-rejected"
GROUP = 'wait_state'
SERVICES = ['stepfunctions']

_BAD = [
    ("negative", {"d": -1}),
    ("non-numeric string", {"d": "abc"}),
    ("fractional", {"d": 1.5}),
    ("absent", {}),
]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A Wait SecondsPath resolving to a negative, non-numeric, fractional or absent value fails the
    execution with States.Runtime and the next state is never entered; a zero-second wait on the
    same machine succeeds, pinning the boundary from both sides.
    """
    definition = {
        "StartAt": "W",
        "States": {
            "W": {"Type": "Wait", "SecondsPath": "$.d", "Next": "After"},
            "After": {"Type": "Pass", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))

    good = _run_execution(ctx, sm_arn, {"d": 0})
    assert good["status"] == "SUCCEEDED", (
        f"control Wait of 0 seconds must succeed, got {good['status']!r} "
        f"error={good.get('error')!r} cause={good.get('cause')!r}"
    )
    assert json.loads(good["output"]) == {"d": 0}, f"control output was {good.get('output')!r}"
    assert _entered(_history(ctx, good["executionArn"])) == ["W", "After"], (
        "control run must pass through W then After"
    )

    for label, payload in _BAD:
        bad = _run_execution(ctx, sm_arn, payload)
        assert bad["status"] == "FAILED", (
            f"[{label}] SecondsPath={payload.get('d')!r} must fail the execution, got "
            f"{bad['status']!r} output={bad.get('output')!r}"
        )
        assert bad.get("error") == "States.Runtime", (
            f"[{label}] expected error 'States.Runtime', got {bad.get('error')!r} "
            f"cause={bad.get('cause')!r}"
        )
        assert "SecondsPath" in (bad.get("cause") or ""), (
            f"[{label}] the cause must name SecondsPath, got {bad.get('cause')!r}"
        )
        entered = _entered(_history(ctx, bad["executionArn"]))
        assert "After" not in entered, (
            f"[{label}] the state after an invalid Wait was entered: {entered!r}"
        )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx, statements=None):
    """An execution role this check owns. Pass/Choice/Wait/Fail machines need no permissions,
    but CreateStateMachine still requires a role Step Functions can assume."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnlang-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn language check role",
        Tags=[{"Key": "sim2real", "Value": "sfn-language"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{role_name}-policy",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlang-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "sfn-language"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_execution(ctx, sm_arn, payload, *, timeout_s=150.0):
    """Start one execution and poll DescribeExecution until it is terminal."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"), input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc
        time.sleep(1)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


def _entered(events):
    """Names of every state entered, in history order."""
    return [e["stateEnteredEventDetails"]["name"] for e in events
            if e["type"].endswith("StateEntered")]


def _exited(events):
    return [e["stateExitedEventDetails"]["name"] for e in events
            if e["type"].endswith("StateExited")]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
