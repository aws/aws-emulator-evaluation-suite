"""dataset-kms-key-associate-disassociate-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dataset-kms-key-associate-disassociate-round-trip"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]

_DATASET_ID = "default"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey attaches a key visible via GetDataset; DisassociateDatasetKmsKey clears it."""
    cw = ctx.client("cloudwatch")
    ctx.client("kms")

    baseline_key_arn = cw.get_dataset(DatasetIdentifier=_DATASET_ID).get("KmsKeyArn")

    key_arn, key_id = _create_cloudwatch_grantable_key(ctx)

    _associate_with_retry(cw, key_arn)
    ctx.on_cleanup(lambda: _restore_baseline(cw, baseline_key_arn))

    got = _poll_until(
        lambda: cw.get_dataset(DatasetIdentifier=_DATASET_ID),
        lambda d: d.get("KmsKeyArn") == key_arn,
        timeout_s=30.0,
    )
    assert got.get("KmsKeyArn") == key_arn, f"expected KmsKeyArn={key_arn}, got {got.get('KmsKeyArn')}"
    assert got["DatasetId"] == "default"
    assert got["Arn"].endswith("dataset/default")

    cw.disassociate_dataset_kms_key(DatasetIdentifier=_DATASET_ID)

    got_after = _poll_until(
        lambda: cw.get_dataset(DatasetIdentifier=_DATASET_ID),
        lambda d: "KmsKeyArn" not in d,
        timeout_s=30.0,
    )
    assert "KmsKeyArn" not in got_after, f"expected no KmsKeyArn after disassociation, got {got_after}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s, last value: {result!r}")


def _create_cloudwatch_grantable_key(ctx):
    """Create a symmetric KMS key whose policy grants both the caller and the
    cloudwatch.amazonaws.com service principal the permissions CloudWatch's dataset
    dry-run validation requires."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudWatchDatasetEncryption",
                "Effect": "Allow",
                "Principal": {"Service": "cloudwatch.amazonaws.com"},
                "Action": [
                    "kms:DescribeKey",
                    "kms:GenerateDataKey",
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                ],
                "Resource": "*",
            },
        ],
    }
    created = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-key-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "cloudwatch-behavioral"}],
    )["KeyMetadata"]
    key_id = created["KeyId"]
    key_arn = created["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_arn, key_id


def _associate_with_retry(cw, key_arn, retries=6):
    """AssociateDatasetKmsKey can transiently ConflictException if another concurrent
    check is mutating the same account/region-singleton default dataset, or
    KmsAccessDeniedException if the key's just-created policy has not yet propagated;
    retry on both."""
    last_err = None
    for attempt in range(retries):
        try:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
            return
        except Exception as err:  # noqa: BLE001
            code = getattr(err, "response", {}).get("Error", {}).get("Code")
            if code in ("ConflictException", "KmsAccessDeniedException") and attempt < retries - 1:
                last_err = err
                time.sleep(2.0 * (attempt + 1))
                continue
            raise
    if last_err:
        raise last_err


def _restore_baseline(cw, baseline_key_arn):
    """The default dataset is an account/region-wide singleton; restore whatever
    KMS association (or lack of one) preceded this check rather than unconditionally
    stripping it."""
    try:
        if baseline_key_arn:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=baseline_key_arn)
        else:
            cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "KmsKeyNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
