"""dataset-kms-key-association-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dataset-kms-key-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]

_DATASET_ID = "default"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey moves the account's default dataset into an
    encrypted state visible via GetDataset; DisassociateDatasetKmsKey reverts it."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Capture baseline so we can restore the account-wide default dataset's
    # encryption configuration exactly as we found it.
    baseline = cw.get_dataset(DatasetIdentifier=_DATASET_ID)
    baseline_kms_arn = baseline.get("KmsKeyArn")

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
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-key-"),
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]

    def _restore_baseline() -> None:
        try:
            if baseline_kms_arn:
                cw.associate_dataset_kms_key(
                    DatasetIdentifier=_DATASET_ID, KmsKeyArn=baseline_kms_arn
                )
            else:
                cw.disassociate_dataset_kms_key(DatasetIdentifier=_DATASET_ID)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "KmsKeyNotFoundException",
                "ResourceNotFoundException",
            ):
                raise

    def _delete_key() -> None:
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    # Register in reverse order: restore-baseline must run BEFORE the key is
    # scheduled for deletion (LIFO -> last registered runs first).
    ctx.on_cleanup(_delete_key)
    ctx.on_cleanup(_restore_baseline)

    # 1. Associate our CMK; eventual KMS-policy propagation may need a retry.
    _retry(
        lambda: cw.associate_dataset_kms_key(
            DatasetIdentifier=_DATASET_ID, KmsKeyArn=key_arn
        ),
        retry_on=("KmsAccessDeniedException",),
        timeout_s=30,
        interval_s=3,
    )

    encrypted = _poll_until(
        lambda: cw.get_dataset(DatasetIdentifier=_DATASET_ID),
        lambda resp: resp.get("KmsKeyArn") == key_arn,
        timeout_s=30,
        interval_s=2,
    )
    assert encrypted["KmsKeyArn"] == key_arn, (
        f"expected GetDataset to reflect associated key {key_arn!r}, got "
        f"{encrypted.get('KmsKeyArn')!r}"
    )
    assert encrypted["DatasetId"] == _DATASET_ID, (
        f"expected DatasetId {_DATASET_ID!r}, got {encrypted.get('DatasetId')!r}"
    )

    # 2. Disassociate; GetDataset reverts to no customer-managed key. Per the API contract,
    # an unassociated dataset OMITS KmsKeyArn entirely rather than returning some other value.
    cw.disassociate_dataset_kms_key(DatasetIdentifier=_DATASET_ID)

    unencrypted = _poll_until(
        lambda: cw.get_dataset(DatasetIdentifier=_DATASET_ID),
        lambda resp: "KmsKeyArn" not in resp,
        timeout_s=30,
        interval_s=2,
    )
    assert "KmsKeyArn" not in unencrypted, (
        f"expected KmsKeyArn absent after disassociation, got {unencrypted.get('KmsKeyArn')!r}"
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s, last value: {last!r}")


def _retry(
    fn: Callable[[], Any],
    *,
    retry_on: tuple[str, ...],
    timeout_s: float = 30.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            last_exc = e
            if code not in retry_on:
                raise
            time.sleep(interval_s)
    if last_exc:
        raise last_exc
    raise AssertionError("retry loop exited without success or exception")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
