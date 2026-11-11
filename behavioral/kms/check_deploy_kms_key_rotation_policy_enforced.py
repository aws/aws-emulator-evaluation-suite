"""deploy-kms-key-rotation-policy-enforced."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-kms-key-rotation-policy-enforced"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A key deployed via CloudFormation with EnableKeyRotation=true actually has
    automatic rotation enabled, per GetKeyRotationStatus -- not just accepted syntax."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    stack_name = ctx.unique_name("sim2real-kms-rot-")
    template = {
        "Resources": {
            "RotatingKey": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": "sim2real rotation-policy test key",
                    "EnableKeyRotation": True,
                    "RotationPeriodInDays": 90,
                    "KeyPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "EnableRootPermissions",
                                "Effect": "Allow",
                                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                                "Action": "kms:*",
                                "Resource": "*",
                            }
                        ],
                    },
                },
            }
        },
        "Outputs": {"KeyId": {"Value": {"Ref": "RotatingKey"}}},
    }

    outputs = _deploy_cfn(ctx, stack_name, template)
    key_id = outputs["KeyId"]

    kms = ctx.client("kms")
    desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert desc["KeyState"] == "Enabled"

    status = kms.get_key_rotation_status(KeyId=key_id)
    assert status["KeyRotationEnabled"] is True
    assert status["RotationPeriodInDays"] == 90

    _teardown_and_verify(ctx, stack_name, key_id)


def _teardown_and_verify(ctx: Any, stack_name: str, key_id: str) -> None:
    """Tearing the stack down must actually schedule the key for deletion at the
    destination -- an independent DescribeKey read, not the stack's own DELETE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    kms = ctx.client("kms")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyState"] == "PendingDeletion", (
        f"stack deletion should schedule the key for deletion, got KeyState={meta['KeyState']!r}"
    )
    assert meta.get("DeletionDate") is not None, "a pending-deletion key must carry a DeletionDate"


def _deploy_cfn(ctx: Any, stack_name: str, template: dict) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
