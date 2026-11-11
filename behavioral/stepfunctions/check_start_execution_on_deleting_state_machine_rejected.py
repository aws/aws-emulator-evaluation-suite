"""start-execution-on-deleting-state-machine-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-execution-on-deleting-state-machine-rejected"
GROUP = "data-plane"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExecution against a state machine that is mid-deletion is rejected with
    StateMachineDeleting, no execution is created, and an unrelated state machine still works."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    definition = json.dumps({"StartAt": "S", "States": {"S": {"Type": "Pass", "End": True}}})
    # A running execution holds a deleted state machine in DELETING until it ends, so the
    # rejections below all land inside that state; teardown stops every running execution.
    held_definition = json.dumps(
        {"StartAt": "W", "States": {"W": {"Type": "Wait", "Seconds": 600, "End": True}}}
    )
    target_arn = _create_state_machine(ctx, role_arn, held_definition)
    control_arn = _create_state_machine(ctx, role_arn, definition)
    held_exec = sfn.start_execution(stateMachineArn=target_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: _stop_running_executions(sfn, target_arn))
    ctx.on_cleanup(lambda: _stop_execution_safe(sfn, held_exec))

    sfn.delete_state_machine(stateMachineArn=target_arn)

    first = _poll_until(
        lambda: _error_while_accepted(lambda: sfn.start_execution(stateMachineArn=target_arn, input="{}")),
        lambda e: e is not None,
        timeout_s=30.0,
        interval_s=0.5,
    )
    expected_message = f"State Machine is being deleted: '{target_arn}'"
    _assert_deleting(first, expected_message, "first")

    # effect bounded: once StateMachineDeleting is observed, it stays rejected on
    # a fresh attempt too (no window where the deleting state machine flips back
    # to accepting new work). Any earlier successes during the deletion race are
    # a valid outcome of the race itself, not a violation.
    second = _client_error(lambda: sfn.start_execution(stateMachineArn=target_arn, input="{}"))
    _assert_deleting(second, expected_message, "second")

    # independent read at the destination: once rejection is steady (both code and code2
    # above agreed), a further attempt must not add a new execution — even though an
    # earlier attempt made during the race window may have (that race is the valid
    # outcome noted above, not something this assertion re-litigates).
    before = sfn.list_executions(stateMachineArn=target_arn)["executions"]
    third = _client_error(lambda: sfn.start_execution(stateMachineArn=target_arn, input="{}"))
    _assert_deleting(third, expected_message, "third")
    after = sfn.list_executions(stateMachineArn=target_arn)["executions"]
    assert len(after) == len(before), (
        f"expected no new execution from a rejected start_execution, "
        f"before={len(before)} after={len(after)}"
    )

    # positive control: an unaffected state machine still starts executions normally.
    control_exec = sfn.start_execution(stateMachineArn=control_arn, input="{}")["executionArn"]
    desc = _poll_until(
        lambda: sfn.describe_execution(executionArn=control_exec),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )
    assert desc["status"] == "SUCCEEDED", f"expected control execution to succeed, got {desc['status']!r}"


def _error_while_accepted(fn):
    """A poll probe: the botocore Error dict once `fn` is refused, None while the deletion race
    still lets it through (an accepted start inside that window is a valid outcome)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]
    return None


def _client_error(fn):
    """The botocore Error dict `fn` raises. An unexpected SUCCESS raises AssertionError, so a
    target accepting a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _assert_deleting(error, expected_message, which):
    assert error.get("Code") == "StateMachineDeleting", (
        f"expected StateMachineDeleting on the {which} attempt, got {error!r}"
    )
    assert error.get("Message") == expected_message, (
        f"expected {expected_message!r} on the {which} attempt, got {error.get('Message')!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-sm-")
    last_err = None
    for _ in range(15):
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
            arn = resp["stateMachineArn"]
            ctx.on_cleanup(lambda: _delete_state_machine_safe(sfn, arn))
            return arn
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


def _stop_execution_safe(sfn, exec_arn: str) -> None:
    """StopExecution, tolerating only an execution that no longer exists."""
    try:
        sfn.stop_execution(executionArn=exec_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _stop_running_executions(sfn, state_machine_arn: str) -> None:
    """Stop each RUNNING execution, including one the deletion race accepted, tolerating only a
    state machine or execution that no longer exists."""
    try:
        pages = sfn.get_paginator("list_executions").paginate(
            stateMachineArn=state_machine_arn, statusFilter="RUNNING"
        )
        arns = [e["executionArn"] for page in pages for e in page["executions"]]
    except ClientError as e:
        if e.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise
        return
    for arn in arns:
        _stop_execution_safe(sfn, arn)


def _delete_state_machine_safe(sfn, arn: str) -> None:
    sfn.delete_state_machine(stateMachineArn=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
