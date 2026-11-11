"""start-execution-sync-heartbeatseconds-over-child-wait-fails-parent."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-execution-sync-heartbeatseconds-over-child-wait-fails-parent"
GROUP = "task_integrations"
SERVICES = ["stepfunctions"]

_CHILD_WAIT_S = 20
_SHORT_HEARTBEAT_S = 5
_LONG_HEARTBEAT_S = 60
_TIMEOUT_ERROR = "States.Timeout"
_IAM_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform",
    "AccessDeniedException",
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """HeartbeatSeconds on a states:startExecution.sync Task is accepted at create; since the
    sync child never sends a heartbeat, the window alone fails the parent States.Timeout before
    the child's longer Wait ends, while a longer-heartbeat twin succeeds."""
    sfn = ctx.client("stepfunctions")
    role_arn = _sync_role(ctx)

    short_child = _create_state_machine(ctx, role_arn, _wait_definition())
    short_parent = _create_state_machine(
        ctx, role_arn, _sync_definition(short_child, _SHORT_HEARTBEAT_S)
    )
    long_child = _create_state_machine(ctx, role_arn, _wait_definition())
    long_parent = _create_state_machine(
        ctx, role_arn, _sync_definition(long_child, _LONG_HEARTBEAT_S)
    )

    short_exec, short_child_exec = _start_until_child(ctx, short_parent)
    long_exec, long_child_exec = _start_until_child(ctx, long_parent)

    short_desc = _poll_terminal(ctx, short_exec, timeout_s=40.0)
    assert short_desc["status"] == "FAILED", (
        f"the {_SHORT_HEARTBEAT_S}s-heartbeat parent ended {short_desc['status']!r}, expected "
        f"FAILED from the heartbeat window alone: {short_desc.get('cause')!r}"
    )
    assert short_desc.get("error") == _TIMEOUT_ERROR, (
        f"expected error {_TIMEOUT_ERROR!r}, got {short_desc.get('error')!r}: "
        f"{short_desc.get('cause')!r}"
    )

    short_types = [e["type"] for e in _history(ctx, short_exec)]
    assert "TaskTimedOut" in short_types, (
        f"expected TaskTimedOut in the heartbeat-failed parent's history, got {short_types!r}"
    )
    assert "TaskSucceeded" not in short_types, (
        f"the heartbeat-failed parent's .sync task closed with a success: {short_types!r}"
    )

    short_child_desc = _poll_terminal(ctx, short_child_exec, timeout_s=30.0)
    assert short_child_desc["status"] == "ABORTED", (
        f"the orphaned child ended {short_child_desc['status']!r} after its parent's heartbeat "
        f"timed out, expected ABORTED: {short_child_desc.get('cause')!r}"
    )

    # Positive control: HeartbeatSeconds longer than the child's Wait never starves the task, so
    # the sync integration delivers the child's own result.
    long_desc = _poll_terminal(ctx, long_exec, timeout_s=60.0)
    assert long_desc["status"] == "SUCCEEDED", (
        f"the {_LONG_HEARTBEAT_S}s-heartbeat twin parent ended {long_desc['status']!r}, expected "
        f"SUCCEEDED: {long_desc.get('error')!r} {long_desc.get('cause')!r}"
    )
    long_child_desc = sfn.describe_execution(executionArn=long_child_exec)
    assert long_child_desc["status"] == "SUCCEEDED", (
        f"the twin's child ended {long_child_desc['status']!r}, expected SUCCEEDED"
    )


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _wait_definition() -> dict:
    return {
        "Comment": "a child that only waits",
        "StartAt": "Hold",
        "States": {"Hold": {"Type": "Wait", "Seconds": _CHILD_WAIT_S, "End": True}},
    }


def _sync_definition(child_arn: str, heartbeat_seconds: int) -> dict:
    return {
        "Comment": "block on the child via .sync with a HeartbeatSeconds window",
        "StartAt": "CallChild",
        "States": {
            "CallChild": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.sync",
                "HeartbeatSeconds": heartbeat_seconds,
                "Parameters": {"StateMachineArn": child_arn, "Input": {"from": "parent"}},
                "End": True,
            }
        },
    }


def _sync_role(ctx) -> str:
    iam = ctx.client("iam")
    account = ctx.account
    role_name = ctx.unique_name("sim2real-behav-sfnsync-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)

    statements = [
        {
            "Effect": "Allow",
            "Action": "states:StartExecution",
            "Resource": f"arn:aws:states:{ctx.region}:{account}:stateMachine:sim2real-behav-*",
        },
        {
            "Effect": "Allow",
            "Action": ["states:DescribeExecution", "states:StopExecution"],
            "Resource": f"arn:aws:states:{ctx.region}:{account}:execution:sim2real-behav-*:*",
        },
        {
            "Effect": "Allow",
            "Action": ["events:PutTargets", "events:PutRule", "events:DescribeRule"],
            "Resource": f"arn:aws:events:{ctx.region}:{account}:rule/"
            "StepFunctionsGetEventsForStepFunctionsExecutionRule",
        },
    ]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded retry at CreateStateMachine and
    # at first .sync use absorbs it.
    return role_arn


def _create_state_machine(ctx, role_arn: str, definition: dict) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(2.0)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last_err!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _start(ctx, sm_arn) -> str:
    arn = ctx.client("stepfunctions").start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"), input="{}"
    )["executionArn"]
    ctx.on_cleanup(lambda a=arn: _best_effort_stop(ctx, a))
    return arn


def _history(ctx, exec_arn) -> list:
    sfn = ctx.client("stepfunctions")
    events: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {"executionArn": exec_arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextToken"):
            return events
        kwargs["nextToken"] = resp["nextToken"]


def _poll_terminal(ctx, exec_arn, *, timeout_s: float) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = sfn.describe_execution(executionArn=exec_arn)
    while last["status"] not in _TERMINAL and time.monotonic() < deadline:
        time.sleep(2.0)
        last = sfn.describe_execution(executionArn=exec_arn)
    if last["status"] not in _TERMINAL:
        raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")
    return last


def _start_until_child(ctx, parent_arn: str, *, attempts: int = 6) -> tuple[str, str]:
    """Start the parent and return (parent, child) once its .sync task has started the child.

    The .sync task is the first runtime use of the role, so an unpropagated policy fails the
    parent with a permissions error; that — and only that — earns a fresh attempt.
    """
    desc = None
    for _ in range(attempts):
        parent = _start(ctx, parent_arn)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            for ev in _history(ctx, parent):
                if ev["type"] == "TaskSubmitted":
                    child = json.loads(ev["taskSubmittedEventDetails"]["output"])["ExecutionArn"]
                    ctx.on_cleanup(lambda a=child: _best_effort_stop(ctx, a))
                    return parent, child
            desc = ctx.client("stepfunctions").describe_execution(executionArn=parent)
            if desc["status"] in _TERMINAL:
                break
            time.sleep(2.0)
        else:
            raise AssertionError(f"parent {parent} never submitted its child within 60s")
        blob = (desc.get("error") or "") + (desc.get("cause") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _IAM_RACE_MARKERS):
            raise AssertionError(
                f"parent ended {desc['status']!r} before starting its child: "
                f"{desc.get('error')!r} {desc.get('cause')!r}"
            )
        time.sleep(5)
    raise AssertionError(f"the parent's role never propagated: {desc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
