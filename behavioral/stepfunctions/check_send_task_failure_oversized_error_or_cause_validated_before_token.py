"""send-task-failure-oversized-error-or-cause-validated-before-token."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-failure-oversized-error-or-cause-validated-before-token"
GROUP = "activities"
SERVICES = ["stepfunctions"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _execution_role_arn(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST))["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retrying AccessDeniedException while a fresh role's trust propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _error(fn) -> tuple[str, str]:
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_activity_task(sfn, activity_arn, *, timeout_s=65):
    # GetActivityTask long-polls up to ~60s server-side; use a fresh poll until a token appears.
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.get_activity_task(activityArn=activity_arn)
        if last.get("taskToken"):
            return last["taskToken"]
        time.sleep(0.5)
    raise AssertionError(f"activity task not scheduled within {timeout_s}s: {last!r}")


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskFailure with a 257-char error or a 32769-char cause is a ValidationException naming
    the violated length, checked before the task token: an unresolvable token gets the same
    ValidationException rather than InvalidToken, and the outstanding task is left untouched.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _execution_role_arn(ctx)

    activity_name = ctx.unique_name("sim2real-behav-act-")
    activity_arn = sfn.create_activity(
        name=activity_name, tags=[{"key": "sim2real", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_activity(activityArn=activity_arn), "ActivityDoesNotExist"))

    definition = {
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": activity_arn, "TimeoutSeconds": 300, "End": True}},
    }
    sm_name = ctx.unique_name("sim2real-behav-sm-")
    sm_arn = _create_sm_retrying(
        sfn, name=sm_name, definition=json.dumps(definition), roleArn=role_arn,
        type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn), "StateMachineDoesNotExist"))

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    task_token = _poll_activity_task(sfn, activity_arn)

    error_constraint = (
        "1 validation error detected: Value at 'error' failed to satisfy constraint: "
        "Member must have length less than or equal to 256"
    )
    cause_constraint = (
        "1 validation error detected: Value at 'cause' failed to satisfy constraint: "
        "Member must have length less than or equal to 32768"
    )

    # With the real, outstanding token: an oversized error or cause is rejected before the task
    # is touched.
    code, msg = _error(lambda: sfn.send_task_failure(taskToken=task_token, error="e" * 257, cause="c"))
    assert (code, msg) == ("ValidationException", error_constraint), (
        f"a 257-char error with a valid token was refused with {code!r} / {msg!r}"
    )
    code, msg = _error(lambda: sfn.send_task_failure(taskToken=task_token, error="e", cause="c" * 32769))
    assert (code, msg) == ("ValidationException", cause_constraint), (
        f"a 32769-char cause with a valid token was refused with {code!r} / {msg!r}"
    )

    still = sfn.describe_execution(executionArn=exec_arn)
    assert still["status"] == "RUNNING", (
        f"a refused SendTaskFailure must leave the execution RUNNING, got {still['status']!r}"
    )

    # The length check runs before the token is resolved at all: a token that cannot possibly
    # exist gets the SAME ValidationException, never InvalidToken.
    bogus_token = "sim2real-no-such-task-token"
    code, msg = _error(lambda: sfn.send_task_failure(taskToken=bogus_token, error="e" * 257, cause="c"))
    assert (code, msg) == ("ValidationException", error_constraint), (
        f"a 257-char error with an unresolvable token must still be refused for its length "
        f"({error_constraint!r}), not for the token, but got {code!r} / {msg!r}"
    )
    code, msg = _error(lambda: sfn.send_task_failure(taskToken=bogus_token, error="e", cause="c" * 32769))
    assert (code, msg) == ("ValidationException", cause_constraint), (
        f"a 32769-char cause with an unresolvable token must still be refused for its length "
        f"({cause_constraint!r}), not for the token, but got {code!r} / {msg!r}"
    )

    # Once the lengths clear the boundary, the SAME unresolvable token is rejected for being a
    # token, proving the length check runs strictly before token resolution rather than in place
    # of it.
    code, msg = _error(lambda: sfn.send_task_failure(taskToken=bogus_token, error="e" * 256, cause="c" * 32768))
    assert (code, msg) == ("InvalidToken", "Invalid Token: 'Invalid token'"), (
        f"a boundary-valued error/cause with an unresolvable token must fail on the token "
        f"(InvalidToken), got {code!r} / {msg!r}"
    )

    # Positive control: the real token, with boundary-valued error and cause, is accepted and
    # fails the execution with exactly those values.
    error, cause = "e" * 256, "c" * 32768
    sfn.send_task_failure(taskToken=task_token, error=error, cause=cause)
    deadline = time.monotonic() + 30
    final = None
    while time.monotonic() < deadline:
        final = sfn.describe_execution(executionArn=exec_arn)
        if final["status"] != "RUNNING":
            break
        time.sleep(0.5)
    assert final["status"] == "FAILED", f"the boundary-valued failure left the execution {final['status']!r}"
    assert (final.get("error"), final.get("cause")) == (error, cause), (
        f"DescribeExecution recorded error={final.get('error')!r} cause-len="
        f"{len(final.get('cause') or '')}, expected the exact boundary values"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
