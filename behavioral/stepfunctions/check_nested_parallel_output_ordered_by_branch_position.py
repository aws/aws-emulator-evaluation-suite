"""nested-parallel-output-ordered-by-branch-position."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nested-parallel-output-ordered-by-branch-position"
GROUP = "parallel_state"
SERVICES = ["stepfunctions"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_sfn_role(ctx) -> str:
    """An execution role this check owns; Parallel/Pass/Wait states call no AWS service."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnnest-role-")
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


def _run_to_terminal(ctx, sm_arn, exec_name, input_data, *, timeout_s=120.0):
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Parallel branch that is itself a Parallel state produces its own
    position-ordered array, nested correctly inside the outer Parallel's own
    branch-ordered output, regardless of which branch finishes first.
    """
    role_arn = _create_sfn_role(ctx)
    sm_name = ctx.unique_name("sim2real-behav-sfnnest-")
    definition = {
        "StartAt": "Outer",
        "States": {
            "Outer": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "Inner",
                        "States": {
                            "Inner": {
                                "Type": "Parallel",
                                "Branches": [
                                    {
                                        "StartAt": "SlowWait",
                                        "States": {
                                            "SlowWait": {"Type": "Wait", "Seconds": 3, "Next": "IA"},
                                            "IA": {"Type": "Pass", "Result": "inner-a", "End": True},
                                        },
                                    },
                                    {
                                        "StartAt": "IB",
                                        "States": {"IB": {"Type": "Pass", "Result": "inner-b", "End": True}},
                                    },
                                ],
                                "End": True,
                            }
                        },
                    },
                    {
                        "StartAt": "MidWait",
                        "States": {
                            "MidWait": {"Type": "Wait", "Seconds": 1, "Next": "OB"},
                            "OB": {"Type": "Pass", "Result": "outer-b", "End": True},
                        },
                    },
                ],
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn, sm_name)

    desc = _run_to_terminal(ctx, sm_arn, ctx.unique_name("sim2real-x-"), {})
    assert desc["status"] == "SUCCEEDED", (
        f"nested Parallel execution must succeed, got {desc['status']!r} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    output = json.loads(desc["output"])
    assert output == [["inner-a", "inner-b"], "outer-b"], (
        "the outer Parallel's branch 0 (the nested Parallel, whose own 3s Wait makes it "
        "the slowest branch) must still land at output position 0 as its own "
        "position-ordered array, and branch 1 ('outer-b', which finishes first) at "
        f"position 1; got {output!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
