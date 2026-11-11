"""disassociate-kms-key-without-prior-association-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disassociate-kms-key-without-prior-association-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateDatasetKmsKey on the default dataset with no key associated is rejected with
    ResourceNotFoundException rather than a no-op success, and changes nothing; the same call
    succeeds while a key is associated."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    original = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")

    def _restore() -> None:
        try:
            if original:
                cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=original)
            else:
                cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "KmsKeyNotFoundException",
                "ResourceNotFoundException",
            ):
                raise

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-key-"),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Policy=json.dumps(_cw_ready_key_policy(account_id)),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    ctx.on_cleanup(_restore)

    # The default dataset is a per-account, per-region singleton that may already have a key.
    _safe_disassociate(cw)
    before = cw.get_dataset(DatasetIdentifier="default")
    assert "KmsKeyArn" not in before, "dataset unexpectedly still has a KMS key associated after normalization"

    # Positive control: the same disassociate call succeeds while a key IS associated, so the
    # rejection below is specific to the nothing-associated precondition.
    _associate_with_retry(cw, key_arn)
    associated = _poll_until(
        lambda: cw.get_dataset(DatasetIdentifier="default"),
        lambda d: d.get("KmsKeyArn") == key_arn,
        timeout_s=30.0,
    )
    assert associated.get("KmsKeyArn") == key_arn, (
        f"expected KmsKeyArn={key_arn} after associate, got {associated.get('KmsKeyArn')!r}"
    )

    cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    after_positive = _poll_until(
        lambda: cw.get_dataset(DatasetIdentifier="default"),
        lambda d: "KmsKeyArn" not in d,
        timeout_s=30.0,
    )
    assert "KmsKeyArn" not in after_positive, "positive-control disassociate did not clear KmsKeyArn"

    # Negative: the identical call, now with nothing associated, is rejected specifically.
    code, message = _error(lambda: cw.disassociate_dataset_kms_key(DatasetIdentifier="default"))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for disassociating a never-associated key, got {code!r}"
    )
    assert message == "No CMK association found for dataset default.", f"unexpected ResourceNotFoundException message {message!r}"

    # Effect must be absent: the dataset's encryption configuration is unchanged.
    after = cw.get_dataset(DatasetIdentifier="default")
    assert "KmsKeyArn" not in after, "dataset unexpectedly gained a KmsKeyArn from a rejected disassociation"
    assert after.get("DatasetId") == before.get("DatasetId")


def _cw_ready_key_policy(account_id: str) -> dict:
    return {
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


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_disassociate(cw: Any) -> None:
    from botocore.exceptions import ClientError

    try:
        cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _associate_with_retry(cw: Any, key_arn: str, timeout_s: float = 30.0, interval_s: float = 3.0) -> None:
    """AssociateDatasetKmsKey can transiently KmsAccessDeniedException while the key policy
    grant to the cloudwatch.amazonaws.com service principal propagates; retry within a bound."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"AssociateDatasetKmsKey never succeeded within {timeout_s}s: {last_exc}")


def _poll_until(probe: Any, predicate: Any, timeout_s: float = 30.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
