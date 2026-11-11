"""create-alias-conflict-duplicate-name."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-alias-conflict-duplicate-name"
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
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachineAlias reusing an alias name with a different routingConfiguration fails with
    ConflictException and the exact message and leaves the alias routed to v1, while repeating the
    original request is idempotent and returns the same alias ARN."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"v": 1}))
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(_asl_pass({"v": 2})))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]

    alias_name = ctx.unique_name("sim2real-behav-alias-dupname-")
    sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
    )
    alias_arn = f"{arn}:{alias_name}"

    # Second create for the SAME name but pointing at a DIFFERENT version is a conflict.
    code, message = _error(
        lambda: sfn.create_state_machine_alias(
            name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v2_arn, "weight": 100}]
        )
    )
    assert code == "ConflictException", f"expected ConflictException for a duplicate alias name, got {code}"
    assert message == (
        "Failed to create alias because an alias with the same name and a different routing "
        "configuration already exists."
    ), f"unexpected ConflictException message {message!r}"

    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert desc["name"] == alias_name, f"expected alias name {alias_name!r}, got {desc['name']!r}"
    assert desc["routingConfiguration"] == [{"stateMachineVersionArn": v1_arn, "weight": 100}], (
        f"original alias routing must be unchanged after a rejected conflicting create: {desc}"
    )

    # Restore leg: the SAME name with the SAME routingConfiguration as already recorded is
    # idempotent (mirrors CreateStateMachine's own identity rule), not a second conflict.
    retry_arn = sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
    )["stateMachineAliasArn"]
    assert retry_arn == alias_arn, (
        f"idempotent re-create of {alias_name!r} with unchanged routing must return the same alias "
        f"ARN, expected {alias_arn!r} got {retry_arn!r}"
    )

    desc_after = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert desc_after["routingConfiguration"] == [{"stateMachineVersionArn": v1_arn, "weight": 100}], (
        f"alias routing must remain unchanged after the idempotent re-create: {desc_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
