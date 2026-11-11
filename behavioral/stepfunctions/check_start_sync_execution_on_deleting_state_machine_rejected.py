"""start-sync-execution-on-deleting-state-machine-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-sync-execution-on-deleting-state-machine-rejected"
GROUP = "express_workflows"
SERVICES = ["stepfunctions"]


def _trust_policy() -> str:
    return json.dumps(
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


def _create_sfn_role(ctx):
    """An execution role this check creates for its own state machines."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_express_state_machine(ctx, role_arn: str) -> str:
    """An EXPRESS state machine, retrying only the AccessDeniedException raised while the
    freshly created role's assume-role grant propagates, polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnsyncdel-")
    definition = json.dumps({"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}})
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="EXPRESS",
                tags=[{"key": "sim2real", "value": "1"}, {"key": "sim2real-check", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: _delete_state_machine_safe(sfn, a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        f"CreateStateMachine(type=EXPRESS) still AccessDenied 120s after the role was created. "
        f"Last error: {last}"
    )


def _delete_state_machine_safe(sfn, arn: str) -> None:
    try:
        sfn.delete_state_machine(stateMachineArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise


def _error_or_none(fn):
    """The botocore Error dict `fn` raises, or None on an accepted call (a valid outcome of the
    deletion race, not a violation — only the terminal, stable rejection is asserted)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    return None


def _poll_until_stable_error(
    probe, expected_code, *, stable_reads=3, timeout_s=120.0, interval_s=2.0
):
    """Poll `probe()` until it reports `expected_code` for `stable_reads` consecutive reads.

    An accepted call or a different code resets the streak: the deletion race can let a call
    through, or answer a different error, before settling (never asserted, only polled past).
    """
    deadline = time.monotonic() + timeout_s
    streak = 0
    last = None
    while time.monotonic() < deadline:
        last = probe()
        streak = streak + 1 if (last is not None and last.get("Code") == expected_code) else 0
        if streak >= stable_reads:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"never settled on a stable {expected_code} within {timeout_s}s; last={last!r}"
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StartSyncExecution against an EXPRESS state machine mid-deletion is rejected with
    StateMachineDeleting; an unrelated EXPRESS machine still runs synchronously."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    target_arn = _create_express_state_machine(ctx, role_arn)
    control_arn = _create_express_state_machine(ctx, role_arn)

    # Positive control before any deletion: the target machine itself runs synchronously.
    before = sfn.start_sync_execution(stateMachineArn=target_arn, input="{}")
    assert before["status"] == "SUCCEEDED", (
        f"positive control: the target machine must run to SUCCEEDED before deletion, "
        f"got {before['status']!r}"
    )

    sfn.delete_state_machine(stateMachineArn=target_arn)

    stable = _poll_until_stable_error(
        lambda: _error_or_none(
            lambda: sfn.start_sync_execution(stateMachineArn=target_arn, input="{}")
        ),
        "StateMachineDeleting",
    )
    expected_message = f"State Machine is being deleted: '{target_arn}'"
    assert stable.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {stable.get('Message')!r}"
    )

    # Positive control: an unaffected EXPRESS machine still runs synchronously.
    control = sfn.start_sync_execution(stateMachineArn=control_arn, input="{}")
    assert control["status"] == "SUCCEEDED", (
        f"positive control: an unrelated EXPRESS machine must still run to SUCCEEDED, "
        f"got {control['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
