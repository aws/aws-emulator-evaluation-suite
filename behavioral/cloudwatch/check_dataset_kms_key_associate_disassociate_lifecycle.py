"""dataset-kms-key-associate-disassociate-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "dataset-kms-key-associate-disassociate-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey attaches a key visible on GetDataset; Disassociate removes it."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    associate = _require_op(cw, "AssociateDatasetKmsKey")
    disassociate = _require_op(cw, "DisassociateDatasetKmsKey")
    get_dataset = _require_op(cw, "GetDataset")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    dataset_arn = f"arn:aws:cloudwatch:{region}:{account_id}:dataset/default"

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAccount",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudWatchDatasetDescribeKey",
                "Effect": "Allow",
                "Principal": {"Service": "cloudwatch.amazonaws.com"},
                "Action": "kms:DescribeKey",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": dataset_arn},
                },
            },
            {
                "Sid": "AllowCloudWatchDatasetEncryption",
                "Effect": "Allow",
                "Principal": {"Service": "cloudwatch.amazonaws.com"},
                "Action": ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "kms:EncryptionContext:aws:cloudwatch:arn": dataset_arn,
                    },
                    "ArnLike": {"aws:SourceArn": dataset_arn},
                },
            },
        ],
    }

    key_meta = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-key-"),
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_arn = key_meta["Arn"]
    key_id = key_meta["KeyId"]

    before = get_dataset(DatasetIdentifier="default")
    original_key_arn = before.get("KmsKeyArn")

    def _restore() -> None:
        _swallow(lambda: disassociate(DatasetIdentifier="default"))
        if original_key_arn:
            _swallow(lambda: associate(DatasetIdentifier="default", KmsKeyArn=original_key_arn))
        _swallow(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    ctx.on_cleanup(_restore)

    associate(DatasetIdentifier="default", KmsKeyArn=key_arn)

    after_associate: dict = {}

    def _kms_matches() -> bool:
        nonlocal after_associate
        after_associate = get_dataset(DatasetIdentifier="default")
        return after_associate.get("KmsKeyArn") == key_arn

    assert _poll_until(_kms_matches, timeout_s=30, interval_s=2), (
        f"GetDataset never reflected the associated KMS key {key_arn!r}, "
        f"last saw KmsKeyArn={after_associate.get('KmsKeyArn')!r}"
    )
    assert after_associate.get("DatasetId") == "default", (
        f"expected DatasetId='default', got {after_associate.get('DatasetId')!r}"
    )

    disassociate(DatasetIdentifier="default")

    after_disassociate: dict = {}

    def _kms_absent() -> bool:
        nonlocal after_disassociate
        after_disassociate = get_dataset(DatasetIdentifier="default")
        return "KmsKeyArn" not in after_disassociate

    assert _poll_until(_kms_absent, timeout_s=30, interval_s=2), (
        "GetDataset still reports a KmsKeyArn after DisassociateDatasetKmsKey, "
        f"last saw KmsKeyArn={after_disassociate.get('KmsKeyArn')!r}"
    )


def _swallow(fn) -> None:
    try:
        fn()
    except Exception:
        pass


def _bound_method(client, operation_name):
    mapping = getattr(client.meta, "method_to_api_mapping", {})
    for method_name, op in mapping.items():
        if op == operation_name:
            return getattr(client, method_name)
    return None


def _require_op(client, operation_name):
    fn = _bound_method(client, operation_name)
    if fn is None:
        raise AssertionError(f"botocore in this environment has no operation {operation_name}")
    return fn


def _poll_until(probe, timeout_s: float = 30.0, interval_s: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if probe():
                return True
        except Exception:
            pass
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
