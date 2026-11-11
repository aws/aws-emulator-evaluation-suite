"""create-alias-routing-weights."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-alias-routing-weights"
GROUP = 'update_versioning'
SERVICES = ['stepfunctions']


_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_execution_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "create-alias-routing-weights"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStateMachineAlias stores the exact version ARNs and weights supplied, summing to 100."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"which": "A"}))
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(_asl_pass({"which": "B"})))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]

    alias_name = ctx.unique_name("sim2real-behav-alias-")
    sfn.create_state_machine_alias(
        name=alias_name,
        routingConfiguration=[
            {"stateMachineVersionArn": v1_arn, "weight": 70},
            {"stateMachineVersionArn": v2_arn, "weight": 30},
        ],
    )
    alias_arn = f"{arn}:{alias_name}"
    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert desc["name"] == alias_name, f"expected name {alias_name!r}, got {desc.get('name')!r}"
    routing = {r["stateMachineVersionArn"]: r["weight"] for r in desc["routingConfiguration"]}
    assert routing == {v1_arn: 70, v2_arn: 30}, f"unexpected routing config: {routing}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
