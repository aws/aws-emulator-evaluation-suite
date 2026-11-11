"""update-state-machine-missing-required-parameter-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-missing-required-parameter-fails"
GROUP = 'error-semantics'
SERVICES = ['stepfunctions']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachine with no updatable field supplied raises MissingRequiredParameter,
    while a call naming an actual updatable field on the identical state machine succeeds."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    arn = _create_state_machine(
        ctx, role_arn, _PASS_DEFINITION, name=ctx.unique_name("sim2real-behav-sfn-update-empty-")
    )

    # Positive control: the identical operation, on the identical state machine, naming a real
    # updatable field, must succeed and the change must be visible via an independent read — this
    # is what separates "rejects a call naming zero fields" from "rejects every UpdateStateMachine".
    sfn.update_state_machine(stateMachineArn=arn, definition=_PASS_DEFINITION_V2)
    described = sfn.describe_state_machine(stateMachineArn=arn)
    assert json.loads(described["definition"]) == json.loads(_PASS_DEFINITION_V2), (
        f"expected the updated definition to be visible, got {described['definition']!r}"
    )

    code, message = _error(lambda: sfn.update_state_machine(stateMachineArn=arn))
    assert code == "MissingRequiredParameter", f"expected MissingRequiredParameter, got {code}"
    assert message == _MISSING_MESSAGE, f"expected message {_MISSING_MESSAGE!r}, got {message!r}"

    # The rejected call must have had no effect: an independent read still shows the definition
    # from the positive control, not something reverted or partially applied.
    described_after = sfn.describe_state_machine(stateMachineArn=arn)
    assert json.loads(described_after["definition"]) == json.loads(_PASS_DEFINITION_V2), (
        f"rejected UpdateStateMachine call must not change state, "
        f"got {described_after['definition']!r}"
    )


_MISSING_MESSAGE = "Either the definition, the role ARN, the LoggingConfiguration, or the TracingConfiguration must be specified"

# A minimal Amazon States Language definition: a single Pass state.
_PASS_DEFINITION = json.dumps(
    {
        "Comment": "Simple pass-through state machine for behavioral checks",
        "StartAt": "PassState",
        "States": {"PassState": {"Type": "Pass", "Result": {"ok": True}, "End": True}},
    }
)

# A distinct definition used to prove UpdateStateMachine can succeed on this same state machine.
_PASS_DEFINITION_V2 = json.dumps(
    {
        "Comment": "Updated pass-through state machine for behavioral checks",
        "StartAt": "PassState",
        "States": {"PassState": {"Type": "Pass", "Result": {"ok": True, "updated": True}, "End": True}},
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
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected UpdateStateMachine to be rejected, but it SUCCEEDED: {result!r}")


def _create_sfn_role(ctx) -> str:
    """An execution role real Step Functions accepts on CreateStateMachine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY
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
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
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
