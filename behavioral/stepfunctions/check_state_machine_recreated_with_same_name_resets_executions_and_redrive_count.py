"""state-machine-recreated-with-same-name-resets-executions-and-redrive-count."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "state-machine-recreated-with-same-name-resets-executions-and-redrive-count"
GROUP = "environment-fidelity"
SERVICES = ["stepfunctions"]

_SFN_TRUST = json.dumps(
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

_PASS_ASL = json.dumps({"StartAt": "Noop", "States": {"Noop": {"Type": "Pass", "End": True}}})


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sfn-recreate-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_SFN_TRUST,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _activity_asl(activity_arn: str) -> str:
    return json.dumps(
        {
            "StartAt": "Work",
            "States": {
                "Work": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "TimeoutSeconds": 120,
                    "End": True,
                }
            },
        }
    )


def _create_with_role_propagation(sfn, **kwargs):
    """CreateStateMachine, retrying AccessDeniedException while a fresh role's trust propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)


def _recreate_with_deleting_retry(sfn, *, deadline, **kwargs):
    """CreateStateMachine under a name whose previous incarnation may still be draining."""
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "StateMachineDeleting"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)


def _delete_and_wait(sfn, arn: str, *, timeout_s: float = 240.0) -> None:
    """Delete, then poll until describe reports it gone. DeleteStateMachine is asynchronous."""
    sfn.delete_state_machine(stateMachineArn=arn)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "StateMachineDoesNotExist":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"{arn} still describes {timeout_s}s after DeleteStateMachine")


def _poll_activity_task(sfn, activity_arn: str, *, timeout_s: float = 90.0) -> str:
    """GetActivityTask long-polls (up to ~60s per call); loop until a task arrives."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName="sim2real-behav")
        if resp.get("taskToken"):
            return resp["taskToken"]
    raise AssertionError(f"no activity task arrived on {activity_arn!r} within {timeout_s}s")


def _wait_status(sfn, exec_arn: str, done, *, timeout_s: float = 90.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if done(last["status"]):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} did not reach the awaited status: {last!r}")


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """Deleting and recreating a state machine under the same name resets its executions: old
    ones vanish from ListExecutions, the execution name is reusable, and a new execution of
    that name starts with redriveCount 0 and later dates than the one it replaced.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _sfn_role(ctx)

    activity_arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-sfn-recreate-act-"),
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["activityArn"]
    ctx.on_cleanup(
        _teardown(lambda: sfn.delete_activity(activityArn=activity_arn), "ActivityDoesNotExist")
    )

    sm_name = ctx.unique_name("sim2real-sfn-recreate-")
    exec_name = ctx.unique_name("sim2real-sfn-recreate-exec-")

    first_sm = _create_with_role_propagation(
        sfn,
        name=sm_name,
        definition=_activity_asl(activity_arn),
        roleArn=role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    first_arn = first_sm["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=first_arn)))

    old_exec_arn = sfn.start_execution(stateMachineArn=first_arn, name=exec_name, input="{}")[
        "executionArn"
    ]

    token = _poll_activity_task(sfn, activity_arn)
    sfn.send_task_failure(
        taskToken=token, error="SimInducedFailure", cause="forced failure for redrive"
    )
    failed = _wait_status(sfn, old_exec_arn, lambda s: s != "RUNNING")
    assert failed["status"] == "FAILED", f"expected FAILED before redrive, got {failed!r}"

    sfn.redrive_execution(executionArn=old_exec_arn)
    token2 = _poll_activity_task(sfn, activity_arn)
    sfn.send_task_success(taskToken=token2, output="{}")
    old_done = _wait_status(sfn, old_exec_arn, lambda s: s not in ("RUNNING", "FAILED"))
    assert old_done["status"] == "SUCCEEDED", f"expected SUCCEEDED after redrive, got {old_done!r}"
    assert old_done["redriveCount"] == 1, (
        f"expected redriveCount 1 on the original execution, got {old_done!r}"
    )

    # --- delete + recreate the state machine under the same name
    _delete_and_wait(sfn, first_arn)
    deadline = time.monotonic() + 240.0
    second_sm = _recreate_with_deleting_retry(
        sfn,
        deadline=deadline,
        name=sm_name,
        definition=_PASS_ASL,
        roleArn=role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    new_arn = second_sm["stateMachineArn"]
    assert new_arn == first_arn, (
        f"the recreated machine's ARN {new_arn!r} differs from the original {first_arn!r}"
    )

    # old executions vanish from ListExecutions on the (reused) ARN
    pages = sfn.get_paginator("list_executions").paginate(stateMachineArn=new_arn)
    names = [e["name"] for page in pages for e in page["executions"]]
    assert names == [], (
        f"ListExecutions on the recreated machine returned {names!r}; the prior incarnation's "
        f"executions must not survive a delete+recreate"
    )

    # the execution name is reusable on the new incarnation
    new_exec_arn = sfn.start_execution(stateMachineArn=new_arn, name=exec_name, input="{}")[
        "executionArn"
    ]
    ctx.on_cleanup(
        _teardown(lambda: sfn.stop_execution(executionArn=new_exec_arn), "ExecutionDoesNotExist")
    )
    assert new_exec_arn == old_exec_arn, (
        f"reusing execution name {exec_name!r} on the recreated machine produced {new_exec_arn!r}, "
        f"expected the same ARN {old_exec_arn!r} since both the machine and execution names are "
        f"unchanged"
    )

    new_done = _wait_status(sfn, new_exec_arn, lambda s: s != "RUNNING")
    assert new_done["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {new_done!r}"
    assert new_done.get("redriveCount", 0) == 0, (
        f"the new execution reusing name {exec_name!r} reports redriveCount "
        f"{new_done.get('redriveCount')!r}; it must start fresh at 0 even though the OLD execution "
        f"of the same name had been redriven to 1"
    )
    assert new_done["startDate"] > old_done["startDate"], (
        f"the new execution's startDate {new_done['startDate']!r} is not later than the original "
        f"execution's {old_done['startDate']!r}"
    )
    assert new_done["stopDate"] > old_done["stopDate"], (
        f"the new execution's stopDate {new_done['stopDate']!r} is not later than the original "
        f"execution's {old_done['stopDate']!r}"
    )

    pages = sfn.get_paginator("list_executions").paginate(stateMachineArn=new_arn)
    names_after = [e["name"] for page in pages for e in page["executions"]]
    assert names_after == [exec_name], (
        f"ListExecutions on the recreated machine after the new run returned {names_after!r}, "
        f"expected exactly the one fresh execution named {exec_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
