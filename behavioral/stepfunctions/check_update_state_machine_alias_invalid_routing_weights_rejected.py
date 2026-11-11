"""update-state-machine-alias-invalid-routing-weights-rejected."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-alias-invalid-routing-weights-rejected"
GROUP = 'update_versioning'
SERVICES = ['stepfunctions']


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
                "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
                "Resource": "*",
            }
        ],
    }
)


def _create_sfn_role(ctx):
    """Create an execution role Step Functions can assume; it is deleted at teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for fn in (
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                fn()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)
    return arn


def _await_role(fn, *, timeout_s=90.0):
    """Call fn(), retrying AccessDeniedException while a new role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    arn = _await_role(lambda: sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
        type=sm_type,
    ))["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises, because a
    target accepting what real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachineAlias with weights summing to 40 fails with ValidationException and the exact
    message and leaves the alias routed 100% to v2, which a valid update just before had set."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"v": 1}))
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(_asl_pass({"v": 2})))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]

    alias_name = ctx.unique_name("sim2real-behav-alias-badupd-")
    sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
    )
    alias_arn = f"{arn}:{alias_name}"

    # Positive control: a valid update on this same alias, via this same operation, must succeed.
    sfn.update_state_machine_alias(
        stateMachineAliasArn=alias_arn,
        routingConfiguration=[{"stateMachineVersionArn": v2_arn, "weight": 100}],
    )
    control = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert control["routingConfiguration"] == [{"stateMachineVersionArn": v2_arn, "weight": 100}], (
        f"positive control: a valid UpdateStateMachineAlias call did not take effect: {control}"
    )

    code, message = _error(
        lambda: sfn.update_state_machine_alias(
            stateMachineAliasArn=alias_arn,
            routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 40}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException for weights summing to 40, got {code}"
    assert message == "Sum of routing configuration weights must equal 100. Received: [40]", (
        f"unexpected ValidationException message: {message!r}"
    )

    # The rejected update must not have touched the alias's routing at all.
    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert desc["routingConfiguration"] == [{"stateMachineVersionArn": v2_arn, "weight": 100}], (
        f"alias routing must be unchanged after a rejected invalid update: {desc}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
