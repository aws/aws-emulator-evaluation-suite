"""sm-alias-update-routing-weights."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sm-alias-update-routing-weights"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Updating an alias's routing configuration changes the weighted version
    split returned by describe."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DEF_V1)
    sfn = ctx.client("stepfunctions")

    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(_DEF_V2))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    alias_arn = sfn.create_state_machine_alias(
        name=ctx.unique_name("sim2real-alias-"),
        routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)))

    initial = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert initial["routingConfiguration"] == [{"stateMachineVersionArn": v1_arn, "weight": 100}], (
        f"expected single-version 100% routing to {v1_arn}, got {initial['routingConfiguration']!r}"
    )

    sfn.update_state_machine_alias(
        stateMachineAliasArn=alias_arn,
        routingConfiguration=[
            {"stateMachineVersionArn": v1_arn, "weight": 40},
            {"stateMachineVersionArn": v2_arn, "weight": 60},
        ],
    )

    # UpdateStateMachineAlias is asynchronous: DescribeStateMachineAlias can
    # briefly keep returning the pre-update routing configuration right after
    # the update call returns, so poll for the new weights instead of
    # asserting immediately.
    expected = {v1_arn: 40, v2_arn: 60}
    weights_by_version = _poll_until(
        lambda: {
            e["stateMachineVersionArn"]: e["weight"]
            for e in sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)["routingConfiguration"]
        },
        lambda w: w == expected,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert weights_by_version == expected, weights_by_version


_DEF_V1 = {
    "Comment": "v1",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "v1", "End": True}},
}
_DEF_V2 = {
    "Comment": "v2",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "v2", "End": True}},
}

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)

    def _cleanup():
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn, definition, *, name=None, sm_type="STANDARD"):
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-sfn-")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
