"""describe-nonexistent-state-machine-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-state-machine-not-found"
GROUP = 'error-semantics'
SERVICES = ['stepfunctions']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachine on a well-formed but never-created ARN raises StateMachineDoesNotExist."""
    sfn = ctx.client("stepfunctions")
    # Derive the bogus ARN from a REAL state machine ARN by perturbing only the
    # name. Fabricating an ARN out of thin air can land outside the probe
    # identity's resource scope and surface AccessDeniedException instead of the
    # not-found semantics we actually want to measure.
    role_arn = _create_sfn_role(ctx)
    real_arn = _create_state_machine(ctx, role_arn, _PASS_DEFINITION)
    bogus_arn = real_arn + "-absent"

    # Positive control: DescribeStateMachine must succeed on the real ARN before we
    # trust it to fail on the perturbed one — otherwise a target that rejects every
    # DescribeStateMachine call would pass this check for the wrong reason.
    control = sfn.describe_state_machine(stateMachineArn=real_arn)
    assert control["stateMachineArn"] == real_arn, (
        f"expected positive control to describe {real_arn}, got {control.get('stateMachineArn')}"
    )

    code, message = _error(lambda: sfn.describe_state_machine(stateMachineArn=bogus_arn))
    assert code == "StateMachineDoesNotExist", f"expected StateMachineDoesNotExist, got {code}"
    expected = f"State Machine Does Not Exist: '{bogus_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# A minimal Amazon States Language definition: a single Pass state.
_PASS_DEFINITION = json.dumps(
    {
        "Comment": "Simple pass-through state machine for behavioral checks",
        "StartAt": "PassState",
        "States": {"PassState": {"Type": "Pass", "Result": {"ok": True}, "End": True}},
    }
)

_SFN_TRUST_POLICY = json.dumps(
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

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                    "states:RedriveExecution",
                    "states:DescribeStateMachine",
                ],
                "Resource": "*",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_sfn_role(ctx) -> str:
    """An execution role real Step Functions accepts on CreateStateMachine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY
    )

    def _cleanup():
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn: str, definition: str, *, name: str | None = None) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
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
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
