"""reject-update-state-machine-on-version-arn."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "reject-update-state-machine-on-version-arn"
GROUP = "overly-permissive"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachine on a published version ARN fails with StateMachineDoesNotExist and the exact
    message, and neither the version nor the base state machine definition changes, while the same
    call on the unqualified ARN succeeds."""
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    name = ctx.unique_name("sim2real-sfn-verarn-")
    definition = json.dumps(
        {"StartAt": "Pass1", "States": {"Pass1": {"Type": "Pass", "End": True}}}
    )
    create_resp = _create_state_machine_with_retry(ctx, name, definition, role_arn)
    sm_arn = create_resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    # Positive control: UpdateStateMachine on the unqualified ARN works, so the rejection
    # below is specific to the version-qualified ARN.
    control_definition = json.dumps(
        {"StartAt": "PassControl", "States": {"PassControl": {"Type": "Pass", "End": True}}}
    )
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=control_definition)
    control_described = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert json.loads(control_described["definition"]) == json.loads(control_definition), (
        "positive control: UpdateStateMachine on the unqualified ARN did not take effect"
    )

    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)[
        "stateMachineVersionArn"
    ]

    new_definition = json.dumps(
        {"StartAt": "Pass2", "States": {"Pass2": {"Type": "Pass", "End": True}}}
    )
    code = message = None
    try:
        sfn.update_state_machine(stateMachineArn=version_arn, definition=new_definition)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")

    assert code is not None, "UpdateStateMachine on a published version ARN unexpectedly succeeded"
    assert code == "StateMachineDoesNotExist", (
        f"expected StateMachineDoesNotExist, got {code}"
    )
    expected = f"State Machine Does Not Exist: '{version_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The version snapshot must remain exactly as it was published -- no silent mutation.
    described = sfn.describe_state_machine(stateMachineArn=version_arn)
    assert json.loads(described["definition"]) == json.loads(control_definition), (
        "version definition changed after a rejected UpdateStateMachine call"
    )

    # The rejected call must not have mutated the unqualified ARN's live definition either.
    base_described = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert json.loads(base_described["definition"]) == json.loads(control_definition), (
        "base state machine definition changed after a rejected UpdateStateMachine call on the version ARN"
    )


def _create_sfn_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine_with_retry(
    ctx: Any, name: str, definition: str, role_arn: str, **kwargs: Any
) -> dict:
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 30
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, **kwargs
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_exc = e
                time.sleep(2)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
