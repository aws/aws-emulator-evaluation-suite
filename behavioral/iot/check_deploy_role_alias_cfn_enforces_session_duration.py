"""deploy-role-alias-cfn-enforces-session-duration."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-role-alias-cfn-enforces-session-duration"
GROUP = "deploy"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation RoleAlias with CredentialDurationSeconds=900 persists 900, while one created
    without the property keeps the 3600s default; deleting the stack removes the alias in IoT."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    iot = ctx.client("iot")

    role_name = ctx.unique_name("sim2real-rolealias-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "credentials.iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    explicit_alias = ctx.unique_name("sim2real-rolealias-explicit-")
    stack_name = ctx.unique_name("sim2real-rolealias-stack-")
    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RoleAlias": {
                    "Type": "AWS::IoT::RoleAlias",
                    "Properties": {
                        "RoleAlias": explicit_alias,
                        "RoleArn": role_arn,
                        "CredentialDurationSeconds": 900,
                    },
                }
            },
        }
    )
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    explicit_desc = iot.describe_role_alias(roleAlias=explicit_alias)["roleAliasDescription"]
    assert explicit_desc["credentialDurationSeconds"] == 900, (
        f"expected the CFN-declared CredentialDurationSeconds=900 to persist, "
        f"got {explicit_desc['credentialDurationSeconds']!r}"
    )

    # control: proves 900 above is the declared value, not a constant echoed back
    default_alias = ctx.unique_name("sim2real-rolealias-default-")
    iot.create_role_alias(
        roleAlias=default_alias, roleArn=role_arn, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: iot.delete_role_alias(roleAlias=default_alias))
    default_desc = iot.describe_role_alias(roleAlias=default_alias)["roleAliasDescription"]
    assert default_desc["credentialDurationSeconds"] == 3600, (
        f"expected the undeclared-property default of 3600s, "
        f"got {default_desc['credentialDurationSeconds']!r}"
    )
    assert default_desc["credentialDurationSeconds"] != explicit_desc["credentialDurationSeconds"], (
        "default-alias duration must differ from the CFN-explicit alias's duration, "
        f"both were {default_desc['credentialDurationSeconds']!r}"
    )

    # IoT itself, not the stack status, must confirm the alias is gone
    _delete_stack(cfn, stack_name)
    code, message = _wait_for_role_alias_gone(iot, explicit_alias)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the CFN-deleted alias, got {code!r}"
    )
    expected = f"Role alias {explicit_alias} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _wait_for_role_alias_gone(iot, role_alias: str, timeout_s: float = 30.0, interval_s: float = 3.0):
    """Poll (bounded, for propagation lag after a stack delete) until the alias is gone; return the
    not-found (code, message), or raise if it never disappears."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.describe_role_alias(roleAlias=role_alias)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return code, err.response["Error"].get("Message")
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"role alias {role_alias!r} still present {timeout_s}s after stack delete"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
