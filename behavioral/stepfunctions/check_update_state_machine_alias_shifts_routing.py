"""update-state-machine-alias-shifts-routing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-alias-shifts-routing"
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
        tags=[{"key": "sim2real-behav-check", "value": CHECK}],
    ))["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _poll_until(probe, predicate, *, timeout_s=20, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachineAlias replaces the routing configuration entirely (not merged with the
    old one).
    """
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"which": "A"}))
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(_asl_pass({"which": "B"})))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]

    alias_name = ctx.unique_name("sim2real-behav-alias-")
    alias_arn = arn + f":{alias_name}"
    sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
    )
    sfn.update_state_machine_alias(
        stateMachineAliasArn=alias_arn,
        routingConfiguration=[{"stateMachineVersionArn": v2_arn, "weight": 100}],
    )
    desc = _poll_until(
        lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn),
        lambda d: d["routingConfiguration"] == [{"stateMachineVersionArn": v2_arn, "weight": 100}],
        description="UpdateStateMachineAlias routing shift visible on DescribeStateMachineAlias",
    )
    assert len(desc["routingConfiguration"]) == 1, (
        f"update must leave exactly one routing entry (replace, not merge with the old one): "
        f"{desc['routingConfiguration']}"
    )
    assert desc["routingConfiguration"][0]["stateMachineVersionArn"] == v2_arn, (
        f"expected routing to point at v2 {v2_arn}, got {desc['routingConfiguration'][0]}"
    )
    assert desc["routingConfiguration"][0]["weight"] == 100, (
        f"expected weight 100 for the sole entry, got {desc['routingConfiguration'][0]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
