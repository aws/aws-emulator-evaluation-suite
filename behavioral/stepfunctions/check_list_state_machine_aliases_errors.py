"""list-state-machine-aliases-errors."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-state-machine-aliases-errors"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStateMachineAliases rejects a corrupted nextToken, maxResults over 1000, a
    nonexistent state machine and a malformed ARN, each with its exact code and message.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, sfn, role_arn)

    control = sfn.list_state_machine_aliases(stateMachineArn=sm_arn)
    assert control["stateMachineAliases"] == [], (
        f"positive control: a freshly created state machine already has aliases: {control!r}"
    )

    token_code, token_message = _error(
        lambda: sfn.list_state_machine_aliases(stateMachineArn=sm_arn, nextToken="not-a-real-token")
    )
    assert token_code == "InvalidToken", f"expected InvalidToken, got {token_code!r}"
    expected_token_message = "Invalid Token: 'Invalid token'"
    assert token_message == expected_token_message, (
        f"expected message {expected_token_message!r}, got {token_message!r}"
    )

    max_results_code, max_results_message = _error(
        lambda: sfn.list_state_machine_aliases(stateMachineArn=sm_arn, maxResults=1001)
    )
    assert max_results_code == "ValidationException", (
        f"expected ValidationException, got {max_results_code!r}"
    )
    expected_max_results_message = (
        "1 validation error detected: Value '1001' at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 1000"
    )
    assert max_results_message == expected_max_results_message, (
        f"expected message {expected_max_results_message!r}, got {max_results_message!r}"
    )

    missing_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{ctx.unique_name('sim2real-behav-sfn-missing-')}"
    missing_code, missing_message = _error(
        lambda: sfn.list_state_machine_aliases(stateMachineArn=missing_arn)
    )
    assert missing_code == "StateMachineDoesNotExist", (
        f"expected StateMachineDoesNotExist, got {missing_code!r}"
    )
    expected_missing_message = f"State Machine Does Not Exist: '{missing_arn}'"
    assert missing_message == expected_missing_message, (
        f"expected message {expected_missing_message!r}, got {missing_message!r}"
    )

    arn_code, arn_message = _error(
        lambda: sfn.list_state_machine_aliases(stateMachineArn="not-an-arn")
    )
    assert arn_code == "InvalidArn", f"expected InvalidArn, got {arn_code!r}"
    expected_arn_message = "Invalid Arn: 'Invalid ARN prefix: not-an-arn'"
    assert arn_message == expected_arn_message, (
        f"expected message {expected_arn_message!r}, got {arn_message!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


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


def _swallow_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "StateMachineDoesNotExist"):
            raise


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_state_machine(ctx, sfn, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's trust policy propagates."""
    name = ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=_PASS_DEFINITION, roleArn=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(
            f"could not create state machine after role propagation wait: {last_err}"
        )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
