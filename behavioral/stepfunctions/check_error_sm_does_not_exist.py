"""error-sm-does-not-exist."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-sm-does-not-exist"
GROUP = 'errors'
SERVICES = ['stepfunctions']

def _role_arn(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
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
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _describe_status(sfn, arn):
    """The machine's status while it is describable, or "GONE" once AWS reports it absent."""
    try:
        return sfn.describe_state_machine(stateMachineArn=arn)["status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "StateMachineDoesNotExist":
            return "GONE"
        raise


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachine on a non-existent SM -> StateMachineDoesNotExist."""
    sfn = ctx.client("stepfunctions")
    # Create a real SM, delete it, then describe — avoids cross-account AccessDenied
    definition = {"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
    arn = _create_state_machine(ctx, definition)
    sfn.delete_state_machine(stateMachineArn=arn)
    # resource deleted by the check; cleanup is idempotent/best-effort
    # DeleteStateMachine is asynchronous: the SM lingers in DELETING and remains
    # describable for a window that can exceed two minutes on real AWS before it
    # finally returns StateMachineDoesNotExist. Poll well past that window.
    _poll_until(
        lambda: _describe_status(sfn, arn),
        lambda status: status == "GONE",
        timeout_s=300,
        interval_s=3.0,
        description="StateMachine fully deleted",
    )
    expected_message = f"State Machine Does Not Exist: '{arn}'"
    code, message = _error_code(lambda: sfn.describe_state_machine(stateMachineArn=arn))
    assert code == "StateMachineDoesNotExist", f"Expected StateMachineDoesNotExist, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Gone must also mean unusable: a mutation on the same dead ARN must fail the
    # same way Describe does, not merely resolve to a stale success.
    start_code, start_message = _error_code(
        lambda: sfn.start_execution(stateMachineArn=arn, input="{}")
    )
    assert start_code == "StateMachineDoesNotExist", (
        f"Expected StartExecution on a deleted state machine to fail with "
        f"StateMachineDoesNotExist, got {start_code!r}"
    )
    expected_start = f"State Machine Does Not Exist: '{arn}'"
    assert start_message == expected_start, f"expected message {expected_start!r}, got {start_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
