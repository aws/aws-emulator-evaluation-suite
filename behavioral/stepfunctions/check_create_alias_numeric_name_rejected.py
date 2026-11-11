"""create-alias-numeric-name-rejected."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-alias-numeric-name-rejected"
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
    """CreateStateMachineAlias with a purely numeric name fails with ValidationException and the exact
    message (it would collide with version ARNs), while a normal name on the same state machine is
    created and is the only alias listed."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"ok": True}))
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]

    control_name = ctx.unique_name("sim2real-behav-alias-ctrl-")
    sfn.create_state_machine_alias(
        name=control_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
    )
    ctx.on_cleanup(
        lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=f"{arn}:{control_name}")
    )

    code, message = _error(
        lambda: sfn.create_state_machine_alias(
            name="12345", routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a purely numeric alias name, got {code}"
    assert message == (
        "1 validation error detected: Value '12345' at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ^(?=.*[a-zA-Z_\\-\\.])[a-zA-Z0-9_\\-\\.]+$"
    ), f"unexpected ValidationException message {message!r}"

    alias_arns = {
        a["stateMachineAliasArn"]
        for a in sfn.list_state_machine_aliases(stateMachineArn=arn)["stateMachineAliases"]
    }
    assert alias_arns == {f"{arn}:{control_name}"}, (
        f"rejected numeric-named alias must not appear alongside the control alias: {alias_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
