"""stop-execution-transitions-running-to-aborted."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stop-execution-transitions-running-to-aborted"
GROUP = "concurrency"
SERVICES = ["stepfunctions"]

_WAIT_SECONDS = 4
_TERMINAL_EVENTS = {
    "ABORTED": "ExecutionAborted",
    "SUCCEEDED": "ExecutionSucceeded",
    "FAILED": "ExecutionFailed",
    "TIMED_OUT": "ExecutionTimedOut",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopExecution racing natural completion ends ABORTED or SUCCEEDED, never stuck RUNNING,
    and the history carries exactly one terminal event matching DescribeExecution's status."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    definition = json.dumps(
        {
            "StartAt": "Wait",
            "States": {
                "Wait": {"Type": "Wait", "Seconds": _WAIT_SECONDS, "Next": "Pass"},
                "Pass": {"Type": "Pass", "End": True},
            },
        }
    )
    sm_name = ctx.unique_name("sim2real-behav-sm-stoprace-")
    sm_arn = _create_state_machine_with_retry(ctx, sfn, sm_name, definition, role_arn)

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))

    # Fire StopExecution right at the edge of the Wait state's deadline to force the race.
    # StopExecution on an already-terminal execution returns 200, so the call is not the signal.
    _poll_until_near_deadline(sfn, exec_arn, budget_s=_WAIT_SECONDS - 0.5)
    sfn.stop_execution(executionArn=exec_arn)

    final_status = _poll_to_terminal(sfn, exec_arn, timeout_s=30.0)
    assert final_status in ("ABORTED", "SUCCEEDED"), (
        f"after the stop/complete race the execution is {final_status!r}; it must be ABORTED (the "
        "stop won) or SUCCEEDED (the Wait state finished first)"
    )

    terminal_events = _poll_terminal_events(sfn, exec_arn, timeout_s=30.0)
    assert terminal_events == [_TERMINAL_EVENTS[final_status]], (
        f"execution is {final_status!r} but its history carries terminal events {terminal_events!r}; "
        f"expected exactly [{_TERMINAL_EVENTS[final_status]!r}]"
    )


def _poll_terminal_events(sfn, exec_arn: str, timeout_s: float = 30.0) -> list:
    """The terminal event types in the execution's history, once the history has caught up with
    DescribeExecution (it can briefly lag a terminal status). Raises if it never does."""
    terminal_types = set(_TERMINAL_EVENTS.values())
    deadline = time.monotonic() + timeout_s
    found = []
    while time.monotonic() < deadline:
        found = [e["type"] for e in _history(sfn, exec_arn) if e["type"] in terminal_types]
        if found:
            return found
        time.sleep(1.0)
    raise AssertionError(f"execution history never recorded a terminal event within {timeout_s}s")


def _history(sfn, exec_arn: str) -> list:
    events = []
    kwargs = {"executionArn": exec_arn}
    while True:
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        if not page.get("nextToken"):
            return events
        kwargs["nextToken"] = page["nextToken"]


def _poll_to_terminal(sfn, exec_arn: str, timeout_s: float = 30.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = "RUNNING"
    while time.monotonic() < deadline:
        status = sfn.describe_execution(executionArn=exec_arn)["status"]
        if status != "RUNNING":
            return status
        time.sleep(0.5)
    raise AssertionError(f"execution never reached a terminal status within {timeout_s}s, stuck at {status!r}")


def _poll_until_near_deadline(sfn, exec_arn: str, budget_s: float, interval_s: float = 0.2) -> str:
    """Poll DescribeExecution until the execution goes terminal or `budget_s` elapses."""
    deadline = time.monotonic() + budget_s
    status = "RUNNING"
    while time.monotonic() < deadline:
        status = sfn.describe_execution(executionArn=exec_arn)["status"]
        if status != "RUNNING":
            return status
        time.sleep(min(interval_s, max(deadline - time.monotonic(), 0)))
    return status


def _create_state_machine_with_retry(ctx, sfn, name: str, definition: str, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while a fresh role propagates."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    sm_arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
    return sm_arn


def _stop_if_running(sfn, exec_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        status = sfn.describe_execution(executionArn=exec_arn)["status"]
        if status == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        # Only an execution that does not exist is already clean.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _create_sfn_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-sfn-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
