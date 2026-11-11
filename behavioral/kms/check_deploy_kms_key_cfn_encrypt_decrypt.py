"""deploy-kms-key-cfn-encrypt-decrypt."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-kms-key-cfn-encrypt-decrypt"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A KMS key deployed via CloudFormation (AWS::KMS::Key) behaviorally supports
    a real Encrypt/Decrypt round trip -- not just CREATE_COMPLETE."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    stack_name = ctx.unique_name("sim2real-kms-cfn-")
    template = {
        "Resources": {
            "TestKey": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": "sim2real behavioral test key",
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
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
                },
            }
        },
        "Outputs": {
            "KeyId": {"Value": {"Ref": "TestKey"}},
            "KeyArn": {"Value": {"Fn::GetAtt": ["TestKey", "Arn"]}},
        },
    }

    kms = ctx.client("kms")
    outputs, key_id = _deploy_cfn(ctx, stack_name, template, kms)

    desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert desc["KeyState"] == "Enabled", f"expected KeyState=Enabled after deploy, got {desc['KeyState']!r}"
    assert desc["Enabled"] is True, f"expected Enabled=True after deploy, got {desc['Enabled']!r}"

    plaintext = b"sim2real-cfn-key-roundtrip-payload"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"decrypt round trip mismatch: expected {plaintext!r}, got {decrypted!r}"


def _deploy_cfn(ctx: Any, stack_name: str, template: dict, kms: Any) -> tuple[dict[str, str], str]:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    key_id = outputs["KeyId"]
    ctx.on_cleanup(lambda: _teardown(cfn, kms, stack_name, key_id))
    return outputs, key_id


def _teardown(cfn: Any, kms: Any, stack_name: str, key_id: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 23}
    )
    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyState"] == "PendingDeletion", (
        f"expected key {key_id} scheduled for deletion after stack teardown, "
        f"got KeyState={meta['KeyState']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
