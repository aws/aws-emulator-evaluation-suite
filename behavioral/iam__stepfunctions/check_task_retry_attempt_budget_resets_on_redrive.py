"""task-retry-attempt-budget-resets-on-redrive."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-retry-attempt-budget-resets-on-redrive"
GROUP = "redrive"
SERVICES = ["iam", "stepfunctions"]

_MAX_ATTEMPTS = 2
_BOGUS_INSTANCE_ID = "i-00000000000000000"
_PROPAGATION_MARKERS = ("authorized to assume the provided role", "cannot be assumed")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A redriven Task with Retry gets its full MaxAttempts budget again: the TaskScheduled
    count after redrive equals the one before, not the exhausted remainder."""
    role_arn = _create_role(ctx)
    sm_arn = _create_state_machine(ctx, _definition(), role_arn)

    exec_arn, desc = _run_to_terminal(ctx, sm_arn)
    assert desc["status"] == "FAILED", (
        f"the always-failing task's execution ended {desc['status']!r}, expected FAILED: "
        f"{desc.get('error')!r} {desc.get('cause')!r}"
    )
    assert desc["error"] == "Ec2.Ec2Exception", f"execution error was {desc['error']!r}"
    assert _mask(desc["cause"]) == _expected_cause(), f"execution cause was {desc['cause']!r}"

    before = _history(ctx, exec_arn)
    scheduled_before = [e for e in before if e["type"] == "TaskScheduled"]
    assert len(scheduled_before) == _MAX_ATTEMPTS + 1, (
        f"{len(scheduled_before)} TaskScheduled event(s) before redrive, expected "
        f"{_MAX_ATTEMPTS + 1} (1 initial attempt + {_MAX_ATTEMPTS} retries)"
    )

    ctx.client("stepfunctions").redrive_execution(executionArn=exec_arn)
    desc2 = _poll_terminal(ctx, exec_arn, redrive_count=1)
    assert desc2["status"] == "FAILED", (
        f"the redriven execution ended {desc2['status']!r}, expected FAILED: "
        f"{desc2.get('error')!r} {desc2.get('cause')!r}"
    )
    assert desc2["error"] == "Ec2.Ec2Exception", f"redriven execution error was {desc2['error']!r}"
    assert _mask(desc2["cause"]) == _expected_cause(), f"redriven execution cause was {desc2['cause']!r}"

    after = _history(ctx, exec_arn)
    redriven_idx = next(i for i, e in enumerate(after) if e["type"] == "ExecutionRedriven")
    scheduled_after = [e for e in after[redriven_idx + 1:] if e["type"] == "TaskScheduled"]
    assert len(scheduled_after) == _MAX_ATTEMPTS + 1, (
        f"{len(scheduled_after)} TaskScheduled event(s) after redrive, expected "
        f"{_MAX_ATTEMPTS + 1} again: a redrive resets the retry attempt count to 0"
    )


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _definition():
    return {
        "StartAt": "Describe",
        "States": {
            "Describe": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ec2:describeInstances",
                "Parameters": {"InstanceIds": [_BOGUS_INSTANCE_ID]},
                "Retry": [{
                    "ErrorEquals": ["Ec2.Ec2Exception"], "IntervalSeconds": 1,
                    "MaxAttempts": _MAX_ATTEMPTS, "BackoffRate": 1.0,
                }],
                "End": True,
            }
        },
    }


def _expected_cause():
    return (
        f'Invalid id: "{_BOGUS_INSTANCE_ID}" (Service: Ec2, Status Code: 400, '
        "Request ID: <id>) (SDK Attempt Count: 1)"
    )


def _mask(cause):
    """AWS embeds a per-call EC2 request id in the cause text; mask only that id."""
    return re.sub(r"Request ID: [0-9a-f-]+\)", "Request ID: <id>)", cause or "")


def _create_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnr-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn redrive execution role", Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    """CreateStateMachine, retried while the just-created role is still propagating in IAM."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnr-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or not any(
                m in exc.response["Error"]["Message"] for m in _PROPAGATION_MARKERS
            ):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _run_to_terminal(ctx, sm_arn, *, timeout_s=90.0, attempts=6):
    """Start a fresh execution while the failure is IAM-trust propagation, not the probe's own.

    Only a fresh execution absorbs the propagation window; a discarded attempt counts nothing.
    """
    sfn = ctx.client("stepfunctions")
    for _ in range(attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _poll_terminal(ctx, exec_arn, timeout_s=timeout_s)
        if desc["status"] != "FAILED" or not any(
            m in (desc.get("cause") or "") for m in _PROPAGATION_MARKERS
        ):
            return exec_arn, desc
        time.sleep(5)
    raise AssertionError("the execution role's trust policy never finished propagating")


def _poll_terminal(ctx, exec_arn, *, redrive_count=0, timeout_s=90.0, interval_s=1.0):
    """DescribeExecution once the execution is terminal after its ``redrive_count``-th redrive."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in _TERMINAL and last.get("redriveCount", 0) == redrive_count:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} did not reach terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
