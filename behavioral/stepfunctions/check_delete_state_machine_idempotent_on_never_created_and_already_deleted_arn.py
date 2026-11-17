"""delete-state-machine-idempotent-on-never-created-and-already-deleted-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-state-machine-idempotent-on-never-created-and-already-deleted-arn"
GROUP = "state_machine_lifecycle"
SERVICES = ["stepfunctions"]

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_PASS_DEFINITION = json.dumps(
    {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _create_state_machine(ctx, sfn, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the fresh role propagates."""
    name = ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_PASS_DEFINITION, roleArn=role_arn
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
    return arn


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises too, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_gone(sfn, arn, *, timeout_s=180.0, interval_s=2.0):
    """Poll DescribeStateMachine past its asynchronous DELETING window to the terminal
    StateMachineDoesNotExist; a transient DELETING read is not proof of deletion."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "StateMachineDoesNotExist":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"state machine {arn} did not fully delete within {timeout_s}s")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStateMachine returns its empty result on an ARN that was never created, and again
    on one already deleted, while a malformed ARN is rejected with InvalidArn and its message.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    # Positive control: DeleteStateMachine really deletes a live state machine.
    live_arn = _create_state_machine(ctx, sfn, role_arn)
    pre = sfn.describe_state_machine(stateMachineArn=live_arn)
    assert pre["status"] == "ACTIVE", f"expected ACTIVE before delete, got {pre['status']!r}"
    delete_resp = sfn.delete_state_machine(stateMachineArn=live_arn)
    body = {k: v for k, v in delete_resp.items() if not k.startswith("ResponseMetadata")}
    assert body == {}, f"expected an empty result from DeleteStateMachine, got {body!r}"
    _poll_gone(sfn, live_arn)

    # A well-formed ARN that was never created: DeleteStateMachine still returns empty, not
    # StateMachineDoesNotExist -- the model declares no not-found error for this operation.
    never_created_arn = (
        f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:"
        f"{ctx.unique_name('sim2real-behav-sfn-never-')}"
    )
    never_resp = sfn.delete_state_machine(stateMachineArn=never_created_arn)
    never_body = {k: v for k, v in never_resp.items() if not k.startswith("ResponseMetadata")}
    assert never_body == {}, (
        f"expected an empty result deleting a never-created ARN, got {never_body!r}"
    )
    never_err = _error(lambda: sfn.describe_state_machine(stateMachineArn=never_created_arn))
    assert never_err[0] == "StateMachineDoesNotExist", (
        f"expected StateMachineDoesNotExist describing the never-created ARN, got {never_err!r}"
    )

    # Repeating DeleteStateMachine on the now-dead live ARN also returns empty: the operation
    # is idempotent, not merely tolerant of ARNs that never existed.
    again_resp = sfn.delete_state_machine(stateMachineArn=live_arn)
    again_body = {k: v for k, v in again_resp.items() if not k.startswith("ResponseMetadata")}
    assert again_body == {}, f"expected an empty result on a second delete, got {again_body!r}"

    # A malformed ARN is a distinct input class and is rejected.
    code, message = _error(lambda: sfn.delete_state_machine(stateMachineArn="not-an-arn"))
    assert code == "InvalidArn", f"expected InvalidArn, got {code!r}"
    expected_message = "Invalid Arn: 'Invalid ARN prefix: not-an-arn'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
