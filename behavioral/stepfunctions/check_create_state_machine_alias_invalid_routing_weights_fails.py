"""create-state-machine-alias-invalid-routing-weights-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-alias-invalid-routing-weights-fails"
GROUP = 'error-semantics'
SERVICES = ['stepfunctions']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachineAlias whose routing weights sum to 42 fails with ValidationException and the
    exact message and creates nothing, while the same call with weights summing to 100 creates an
    alias with that routing."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    arn = _create_state_machine(
        ctx, role_arn, _PASS_DEFINITION, name=ctx.unique_name("sim2real-behav-sfn-alias-invalid-")
    )
    version_arn = sfn.publish_state_machine_version(stateMachineArn=arn)[
        "stateMachineVersionArn"
    ]
    # A published version PINS the state machine: DeleteStateMachine is refused
    # while any version survives, so the version teardown must run BEFORE the
    # state machine's (cleanups are LIFO, so registering it here is correct).
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn)
        )
    )
    # A target that WRONGLY accepts the invalid weights would otherwise leak an
    # alias that itself pins the version, so sweep every alias of this state
    # machine at cleanup regardless of which of the two calls below "succeeded".
    ctx.on_cleanup(lambda: _delete_aliases_of(sfn, arn))

    # Positive control: identical shape, weights sum to 100, must succeed.
    control_name = ctx.unique_name("sim2real-behav-alias-control-")
    control_arn = sfn.create_state_machine_alias(
        name=control_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]
    control_desc = sfn.describe_state_machine_alias(stateMachineAliasArn=control_arn)
    assert control_desc["routingConfiguration"] == [
        {"stateMachineVersionArn": version_arn, "weight": 100}
    ], f"positive control alias was not created as requested: {control_desc}"

    invalid_name = ctx.unique_name("sim2real-behav-alias-invalid-")
    code, message = _error(
        lambda: sfn.create_state_machine_alias(
            name=invalid_name,
            routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 42}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "Sum of routing configuration weights must equal 100. Received: [42]", (
        f"unexpected ValidationException message {message!r}"
    )

    # Independent read: the rejected call must not have created anything, while the positive control
    # (created moments earlier) is still there. AliasListItem carries no "name" field, only the ARN,
    # so the name is the ARN's trailing segment.
    alias_names = {
        a["stateMachineAliasArn"].rsplit(":", 1)[-1]
        for a in sfn.list_state_machine_aliases(stateMachineArn=arn)["stateMachineAliases"]
    }
    assert invalid_name not in alias_names, (
        f"an alias leaked despite the rejected create call: {alias_names}"
    )
    assert control_name in alias_names, (
        f"positive control alias is missing from the listing: {alias_names}"
    )


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
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


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


def _delete_aliases_of(sfn, state_machine_arn: str) -> None:
    """Aliases pin versions, and a pinned version blocks deletion, so unwind
    alias -> version -> state machine in that order."""
    try:
        aliases = sfn.list_state_machine_aliases(stateMachineArn=state_machine_arn).get(
            "stateMachineAliases", []
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFound", "StateMachineDoesNotExist"):
            raise
        return
    for alias in aliases:
        _swallow(
            lambda a=alias: sfn.delete_state_machine_alias(
                stateMachineAliasArn=a["stateMachineAliasArn"]
            )
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
