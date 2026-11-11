"""update-state-machine-alias-no-fields-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-alias-no-fields-rejected"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]

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

_PASS_DEFINITION = json.dumps(
    {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """The AWS error `fn` raised, as {"Code", "Message"}. An unexpected success raises, so a
    target that accepts what AWS refuses can never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message") or ""}
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=_PASS_DEFINITION, roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(5)
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachineAlias with neither description nor routingConfiguration fails with
    ValidationException and its exact message, leaving the alias untouched.
    """
    sfn = ctx.client("stepfunctions")
    sm_arn = _create_state_machine(ctx, _create_sfn_role(ctx))
    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    alias_name = ctx.unique_name("sim2real-behav-alias-")
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(
        _teardown(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn), "ResourceNotFound")
    )

    # Positive control: an update naming a field, on this same alias and operation, succeeds.
    sfn.update_state_machine_alias(stateMachineAliasArn=alias_arn, description="before the empty call")
    control = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert control["description"] == "before the empty call", (
        f"positive control: UpdateStateMachineAlias with a description did not take effect: {control!r}"
    )

    err = _error(lambda: sfn.update_state_machine_alias(stateMachineAliasArn=alias_arn))
    expected = {
        "Code": "ValidationException",
        "Message": "Either description or routing configuration must be specified",
    }
    assert err == expected, f"UpdateStateMachineAlias with neither field: expected {expected}, got {err}"

    # The rejected call must not have touched the alias at all.
    after = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert after["description"] == "before the empty call", (
        f"alias description changed after a rejected field-less update: {after!r}"
    )
    assert after["routingConfiguration"] == [{"stateMachineVersionArn": version_arn, "weight": 100}], (
        f"alias routing changed after a rejected field-less update: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
