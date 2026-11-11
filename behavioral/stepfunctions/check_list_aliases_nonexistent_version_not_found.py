"""list-aliases-nonexistent-version-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-aliases-nonexistent-version-not-found"
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
    """ListStateMachineAliases against a version ARN that was never published fails with
    ResourceNotFound and the version ARN's exact message.
    """
    sfn = ctx.client("stepfunctions")
    sm_arn = _create_state_machine(ctx, _create_sfn_role(ctx))

    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(
        _teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn), "ResourceNotFound")
    )
    alias_name = ctx.unique_name("sim2real-behav-alias-")
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}]
    )["stateMachineAliasArn"]
    ctx.on_cleanup(
        _teardown(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn), "ResourceNotFound")
    )

    # Positive control: listing the version that does exist, on this same state machine and
    # operation, finds the alias just created.
    control = sfn.list_state_machine_aliases(stateMachineArn=version_arn)
    control_arns = {a["stateMachineAliasArn"] for a in control["stateMachineAliases"]}
    expected_control = {alias_arn}
    assert control_arns == expected_control, (
        f"positive control: expected {expected_control!r}, got {control_arns!r}"
    )

    # The published version is ":1"; no version "2" was ever published on this state machine, so
    # this ARN names a version that never existed, unambiguously.
    never_published_arn = f"{sm_arn}:2"
    err = _error(lambda: sfn.list_state_machine_aliases(stateMachineArn=never_published_arn))
    expected = {"Code": "ResourceNotFound", "Message": f"Resource not found: '{never_published_arn}'"}
    assert err == expected, f"ListStateMachineAliases on a never-published version: expected {expected}, got {err}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
