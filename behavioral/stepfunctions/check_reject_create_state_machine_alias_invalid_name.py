"""reject-create-state-machine-alias-invalid-name."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "reject-create-state-machine-alias-invalid-name"
GROUP = "overly-permissive"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStateMachineAlias with a name outside the alias name pattern fails with ValidationException
    and the exact pattern message, while a valid name on the same version is created and describable."""
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    name = ctx.unique_name("sim2real-sfn-alias-sm-")
    definition = json.dumps(
        {"StartAt": "Pass1", "States": {"Pass1": {"Type": "Pass", "End": True}}}
    )
    create_resp = _create_state_machine_with_retry(ctx, name, definition, role_arn)
    sm_arn = create_resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)[
        "stateMachineVersionArn"
    ]

    invalid_name = "bad alias name! (not allowed)"
    code = message = None
    try:
        sfn.create_state_machine_alias(
            name=invalid_name,
            routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")

    assert code is not None, "CreateStateMachineAlias with an invalid name unexpectedly succeeded"
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        f"1 validation error detected: Value '{invalid_name}' at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ^(?=.*[a-zA-Z_\\-\\.])[a-zA-Z0-9_\\-\\.]+$"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Sanity: a name that satisfies the naming pattern is accepted.
    valid_name = ctx.unique_name("sim2real-alias-")
    alias_resp = sfn.create_state_machine_alias(
        name=valid_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )
    alias_arn = alias_resp["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn))
    described = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert described["name"] == valid_name, (
        f"expected describe_state_machine_alias to report name={valid_name!r}, "
        f"got {described['name']!r}"
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
