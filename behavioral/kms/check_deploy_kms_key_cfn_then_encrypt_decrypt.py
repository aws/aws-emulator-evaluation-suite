"""deploy-kms-key-cfn-then-encrypt-decrypt."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-kms-key-cfn-then-encrypt-decrypt"
GROUP = "deploy"
SERVICES = ["kms"]

ERR_KMS_INVALID_STATE = "KMSInvalidStateException"


def _client_error(ctx, fn, timeout_s=60.0):
    """The error fn() is refused with, polled every 2 s: KMS applies a key-state change
    eventually, so a call can still succeed briefly after DescribeKey shows the new state."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to fail, but it still succeeded after {timeout_s}s")
        time.sleep(2)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS::KMS::Key deployed via CloudFormation produces a usable KeyId/Arn that
    supports a real Encrypt/Decrypt round trip after stack CREATE_COMPLETE."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    stack_name = ctx.unique_name("sim2real-behav-kmskey-")
    template = json.dumps(
        {
            "Resources": {
                "Key": {
                    "Type": "AWS::KMS::Key",
                    "Properties": {
                        "Description": "sim2real behavioral check key",
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
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyId"] == key_id, f"expected KeyId {key_id}, got {described['KeyId']}"
    assert described["Arn"] == key_arn, f"expected Arn {key_arn}, got {described['Arn']}"
    assert described["KeyState"] == "Enabled", f"expected KeyState Enabled, got {described['KeyState']}"
    assert described["Enabled"] is True, f"expected Enabled True, got {described['Enabled']}"

    plaintext = b"sim2real-kms-cfn-roundtrip"
    ciphertext = kms.encrypt(KeyId=key_arn, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_arn)
    assert decrypted["Plaintext"] == plaintext, "decrypted plaintext did not match what was encrypted"
    assert decrypted["KeyId"] == key_arn, f"expected decrypt KeyId {key_arn}, got {decrypted['KeyId']}"

    _delete_stack(ctx, stack_name)

    torn_down = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert torn_down["KeyState"] == "PendingDeletion", (
        f"expected KeyState PendingDeletion after stack teardown, got {torn_down['KeyState']}"
    )
    assert torn_down["Enabled"] is False, f"expected Enabled False after teardown, got {torn_down['Enabled']}"

    err = _client_error(ctx, lambda: kms.encrypt(KeyId=key_arn, Plaintext=plaintext))
    assert err["Code"] == ERR_KMS_INVALID_STATE, (
        f"expected {ERR_KMS_INVALID_STATE} for encrypt on a torn-down (pending-deletion) key, got {err}"
    )
    expected = f"{key_arn} is pending deletion."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"


def _deploy_stack(ctx: Any, stack_name: str, template_body: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body, OnFailure="ROLLBACK")
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))


def _delete_stack(ctx: Any, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_gone(ctx, stack_name)


def _wait_for_stack_gone(ctx: Any, stack_name: str, timeout_s: float = 300.0, interval_s: float = 2.0) -> None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if "does not exist" in exc.response["Error"].get("Message", ""):
                return
            raise
        status = resp["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} teardown failed: DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE within {timeout_s}s")


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
