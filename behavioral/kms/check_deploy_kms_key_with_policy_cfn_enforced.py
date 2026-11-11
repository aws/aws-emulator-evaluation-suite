"""deploy-kms-key-with-policy-cfn-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-kms-key-with-policy-cfn-enforced"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A KeyPolicy in a CFN AWS::KMS::Key is returned exactly and enforced: Encrypt succeeds,
    the explicitly denied Decrypt raises AccessDeniedException despite an Allow of kms:*, and
    after PutKeyPolicy drops the Deny the same ciphertext decrypts.
    """
    principal_arn = _resolve_principal_arn(ctx)
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPrincipalAdmin",
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "DenyDecrypt",
                "Effect": "Deny",
                "Principal": {"AWS": principal_arn},
                "Action": "kms:Decrypt",
                "Resource": "*",
            },
        ],
    }
    template = {
        "Parameters": {"PrincipalArn": {"Type": "String"}},
        "Resources": {
            "TestKey": {
                "Type": "AWS::KMS::Key",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "Description": ctx.unique_name("sim2real-kms-cfn-"),
                    "Tags": [
                        {"Key": "sim2real", "Value": "deploy-kms-key-with-policy-cfn-enforced"}
                    ],
                    "KeyPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowPrincipalAdmin",
                                "Effect": "Allow",
                                "Principal": {"AWS": {"Ref": "PrincipalArn"}},
                                "Action": "kms:*",
                                "Resource": "*",
                            },
                            {
                                "Sid": "DenyDecrypt",
                                "Effect": "Deny",
                                "Principal": {"AWS": {"Ref": "PrincipalArn"}},
                                "Action": "kms:Decrypt",
                                "Resource": "*",
                            },
                        ],
                    },
                },
            }
        },
        "Outputs": {
            "KeyId": {"Value": {"Ref": "TestKey"}},
            "KeyArn": {"Value": {"Fn::GetAtt": ["TestKey", "Arn"]}},
        },
    }

    outputs = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters=[{"ParameterKey": "PrincipalArn", "ParameterValue": principal_arn}],
    )
    key_id = outputs["KeyId"]

    kms = ctx.client("kms")
    returned_policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    assert returned_policy == policy_doc, f"policy mismatch: {returned_policy} != {policy_doc}"

    # Positive control: the allow statement covers Encrypt.
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=b"cfn-policy-probe")["CiphertextBlob"]

    # Negative: the explicit Deny statement blocks Decrypt for the very same principal/key.
    err = _error(lambda: kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext))
    assert err.get("Code") == "AccessDeniedException", err
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: kms:Decrypt on resource: "
        f"{outputs['KeyArn']} with an explicit deny in a resource-based policy"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Drop only the DenyDecrypt statement: the identical decrypt succeeding proves the refusal
    # came from that statement, as the Allow already covers kms:* including Decrypt.
    restored_policy = {**policy_doc, "Statement": [policy_doc["Statement"][0]]}
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(restored_policy))

    def _decrypt_after_restore():
        try:
            return kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            return None

    plaintext = _poll_until(
        _decrypt_after_restore,
        lambda p: p is not None,
        timeout_s=60,
        interval_s=3,
        description="Decrypt succeeds again once DenyDecrypt is removed from the key policy",
    )
    assert plaintext == b"cfn-policy-probe", plaintext


def _resolve_principal_arn(ctx) -> str:
    sts = ctx.client("sts")
    arn = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        # Resource policies must reference the IAM role, not the STS session ARN.
        _, _, rest = arn.partition(":assumed-role/")
        role_name = rest.split("/")[0]
        account_id = arn.split(":")[4]
        return f"arn:aws:iam::{account_id}:role/{role_name}"
    return arn


def _deploy_cfn(ctx, template_body: str, parameters=None) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-kms-cfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters or [],
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
