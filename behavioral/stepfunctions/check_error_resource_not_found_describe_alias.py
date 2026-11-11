"""error-resource-not-found-describe-alias."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-resource-not-found-describe-alias"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachineAlias on a never-created alias of a real state machine fails with
    ResourceNotFound and the exact message, while a real alias on the same state machine describes."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _PASS_DEFINITION)
    sfn = ctx.client("stepfunctions")

    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    alias_name = ctx.unique_name("sim2real-alias-")
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)))

    # Positive control: the real alias, on the real state machine, describes cleanly.
    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert desc["name"] == alias_name, f"expected {alias_name!r}, got {desc['name']!r}"

    # Perturb only the alias name, keeping the real state machine ARN intact, so a ResourceNotFound
    # here is unambiguously about the never-created alias — not about the caller's scope to the
    # state machine itself.
    bogus_alias_arn = alias_arn + "-absent"
    code, message = _refusal(lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=bogus_alias_arn))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected_message = f"Resource not found: '{bogus_alias_arn}'"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


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


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


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
    from botocore.exceptions import ClientError

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
