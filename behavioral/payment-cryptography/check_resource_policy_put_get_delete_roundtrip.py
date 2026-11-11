"""resource-policy-put-get-delete-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-put-get-delete-roundtrip"
GROUP = "state"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A key starts with no resource policy attached; PutResourcePolicy attaches one that
    GetResourcePolicy returns verbatim, and DeleteResourcePolicy detaches it again."""
    pc = ctx.client("payment-cryptography")
    key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    created = pc.create_key(
        KeyAttributes=key_attributes,
        Exportable=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Key"]
    arn = created["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))

    no_policy = pc.get_resource_policy(ResourceArn=arn)
    assert no_policy["Policy"] == "{}", f"expected no policy attached, got {no_policy['Policy']!r}"

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountRole",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "payment-cryptography:GetPublicKeyCertificate",
                "Resource": "*",
            }
        ],
    }
    policy_document = json.dumps(policy)
    put = pc.put_resource_policy(ResourceArn=arn, Policy=policy_document)
    assert put["ResourceArn"] == arn, f"expected PutResourcePolicy to echo {arn}, got {put['ResourceArn']!r}"
    ctx.on_cleanup(lambda: _safe_delete_policy(pc, arn))

    fetched = pc.get_resource_policy(ResourceArn=arn)
    assert fetched["ResourceArn"] == arn, f"expected GetResourcePolicy to echo {arn}, got {fetched['ResourceArn']!r}"
    actual_policy = json.loads(fetched["Policy"])
    assert actual_policy == policy, f"policy mismatch: {actual_policy!r} != {policy!r}"

    pc.delete_resource_policy(ResourceArn=arn)
    after_delete = pc.get_resource_policy(ResourceArn=arn)
    assert after_delete["Policy"] == "{}", (
        f"expected policy detached after DeleteResourcePolicy, got {after_delete['Policy']!r}"
    )


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_policy(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_resource_policy(ResourceArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
