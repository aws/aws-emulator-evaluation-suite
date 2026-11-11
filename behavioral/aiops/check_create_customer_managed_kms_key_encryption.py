"""create-customer-managed-kms-key-encryption."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-customer-managed-kms-key-encryption"
GROUP = "state"
SERVICES = ["aiops"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """Supplying a customer managed KMS key on create is echoed back as CUSTOMER_MANAGED_KMS_KEY with the matching kmsKeyId."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)
    key_arn = _create_kms_key(ctx)

    _name, arn = _create_group(
        ctx,
        aiops,
        role_arn,
        encryptionConfiguration={"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn},
    )

    got = aiops.get_investigation_group(identifier=arn)
    enc = got["encryptionConfiguration"]
    assert enc["type"] == "CUSTOMER_MANAGED_KMS_KEY"
    assert enc["kmsKeyId"] == key_arn


_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "aiops.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-aiops-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_kms_key(ctx) -> str:
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description=ctx.unique_name("sim2real-aiops-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    key_arn = resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # AIOps needs kms:DescribeKey / kms:Decrypt / kms:GenerateDataKey on the key, scoped to
    # this account's investigation groups, or CreateInvestigationGroup fails with
    # AccessDeniedException ("Service is not authorized to perform kms:DescribeKey").
    account = ctx.client("sts").get_caller_identity()["Account"]
    ig_arn_pattern = f"arn:aws:aiops:{ctx.region}:{account}:investigation-group/*"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAccountFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowAIOpsServiceDescribeKey",
                "Effect": "Allow",
                "Principal": {"Service": "aiops.amazonaws.com"},
                "Action": ["kms:DescribeKey"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "StringLike": {"aws:SourceArn": ig_arn_pattern},
                },
            },
            {
                "Sid": "AllowAIOpsServiceDecryptGenerateDataKey",
                "Effect": "Allow",
                "Principal": {"Service": "aiops.amazonaws.com"},
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "StringLike": {"aws:SourceArn": ig_arn_pattern},
                },
            },
        ],
    }
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))
    return key_arn


def _create_group(ctx, aiops, role_arn: str, **kwargs):
    name = ctx.unique_name("sim2real-ig-")
    deadline = time.monotonic() + 150.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = aiops.create_investigation_group(name=name, roleArn=role_arn, **kwargs)
            arn = resp["arn"]
            ctx.on_cleanup(lambda a=arn: aiops.delete_investigation_group(identifier=a))
            return name, arn
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if (
                code == "ResourceNotFoundException"
                or code == "AccessDeniedException"
                or code == "ServiceQuotaExceededException"
                or (code == "ValidationException" and "assume" in msg.lower())
            ):
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
