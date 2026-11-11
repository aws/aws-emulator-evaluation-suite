"""deploy-kms-alias-cfn-then-resolve."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-kms-alias-cfn-then-resolve"
GROUP = "deploy"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS::KMS::Alias deployed via CloudFormation pointing at a key resolves
    correctly: Encrypt via the alias name/ARN succeeds and ListAliases shows the
    AliasName -> TargetKeyId binding."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    stack_name = ctx.unique_name("sim2real-behav-kmsalias-")
    alias_name = ctx.unique_name("alias/sim2real-behav-")
    template = json.dumps(
        {
            "Resources": {
                "Key": {
                    "Type": "AWS::KMS::Key",
                    "Properties": {
                        "Description": "sim2real behavioral alias check key",
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
                        "Tags": [{"Key": "Name", "Value": stack_name}],
                    },
                },
                "Alias": {
                    "Type": "AWS::KMS::Alias",
                    "Properties": {
                        "AliasName": alias_name,
                        "TargetKeyId": {"Ref": "Key"},
                    },
                },
            },
            "Outputs": {
                "KeyId": {"Value": {"Ref": "Key"}},
                "KeyArn": {"Value": {"Fn::GetAtt": "Key.Arn"}},
            },
        }
    )
    _deploy_stack(ctx, stack_name, template)
    status = _wait_for_stack_status(ctx, stack_name)
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE: {status}"

    outputs = _stack_outputs(ctx, stack_name)
    key_id = outputs["KeyId"]
    key_arn = outputs["KeyArn"]

    kms = ctx.client("kms")

    # DescribeKey resolves the alias name to the same underlying key.
    described = kms.describe_key(KeyId=alias_name)["KeyMetadata"]
    assert described["KeyId"] == key_id, f"alias {alias_name} resolved to {described['KeyId']!r}, expected {key_id!r}"
    assert described["Arn"] == key_arn, f"alias {alias_name} resolved to arn {described['Arn']!r}, expected {key_arn!r}"

    # ListAliases shows the CFN-created binding.
    aliases = kms.list_aliases(KeyId=key_id)["Aliases"]
    matching = [a for a in aliases if a["AliasName"] == alias_name]
    assert len(matching) == 1, f"expected exactly one alias {alias_name} bound to {key_id}, got {aliases}"
    assert matching[0]["TargetKeyId"] == key_id, (
        f"ListAliases bound {alias_name} to {matching[0]['TargetKeyId']!r}, expected {key_id!r}"
    )

    # Encrypt via the alias resolves to the underlying key material and round-trips.
    plaintext = b"sim2real-kms-alias-roundtrip"
    ciphertext = kms.encrypt(KeyId=alias_name, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)
    assert decrypted["Plaintext"] == plaintext, f"decrypt roundtrip mismatch: got {decrypted['Plaintext']!r}"
    assert decrypted["KeyId"] == key_arn, f"ciphertext decrypted under {decrypted['KeyId']!r}, expected {key_arn!r}"

    # Teardown is proven, not assumed: delete the stack and confirm it, and the alias binding
    # it created, are both actually gone via an independent read.
    _delete_stack(ctx, stack_name)
    try:
        kms.describe_key(KeyId=alias_name)
        raise AssertionError(f"alias {alias_name} still resolves after stack {stack_name} was deleted")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "NotFoundException", (
            f"expected NotFoundException for deleted alias {alias_name}, got {exc.response['Error']['Code']}"
        )
        alias_arn = f"arn:aws:kms:{ctx.region}:{ctx.account}:{alias_name}"
        expected_message = f"Alias {alias_arn} is not found."
        assert exc.response["Error"].get("Message") == expected_message, (
            f"expected message {expected_message!r} for deleted alias, got {exc.response['Error'].get('Message')!r}"
        )
    aliases_after = kms.list_aliases(KeyId=key_id)["Aliases"]
    assert not any(a["AliasName"] == alias_name for a in aliases_after), (
        f"alias {alias_name} still listed under {key_id} after stack deletion"
    )


def _deploy_stack(ctx: Any, stack_name: str, template_body: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body, OnFailure="ROLLBACK")
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))


def _delete_stack(ctx: Any, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_gone(ctx, stack_name)


def _wait_for_stack_gone(ctx: Any, stack_name: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        stacks = resp["Stacks"]
        if not stacks:
            return
        last_status = stacks[0]["StackStatus"]
        if last_status == "DELETE_COMPLETE":
            return
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED while tearing down")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE within {timeout_s}s (last={last_status})")


def _wait_for_stack_status(ctx: Any, stack_name: str, timeout_s: float = 600.0, interval_s: float = 10.0) -> str:
    cfn = ctx.client("cloudformation")
    terminal = {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
    }
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state in {timeout_s}s (last={status})")


def _stack_outputs(ctx: Any, stack_name: str) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = resp["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
