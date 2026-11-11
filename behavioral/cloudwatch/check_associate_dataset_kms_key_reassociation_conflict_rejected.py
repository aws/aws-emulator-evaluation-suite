"""associate-dataset-kms-key-reassociation-conflict-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-dataset-kms-key-reassociation-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey rejects a key without a CloudWatch grant, and does not mutate state. Real CloudWatch surfaces the under-permissioned key rejection as
a generic `AccessDenied` error rather than a KMS-specific exception (matching its behavior
for other KMS-key related failures, such as a nonexistent key)."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    dataset_arn = f"arn:aws:cloudwatch:{region}:{account_id}:dataset/default"

    good_policy = {
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
                "Sid": "AllowCloudWatchDatasetUse",
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
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": dataset_arn},
                },
            },
        ],
    }

    good_key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-cw-dataset-good-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Policy=json.dumps(good_policy),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    good_key_id, good_key_arn = good_key["KeyId"], good_key["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: kms.schedule_key_deletion(KeyId=good_key_id, PendingWindowInDays=7)))

    bad_key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-cw-dataset-bad-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]  # default policy: root only, no cloudwatch.amazonaws.com grant
    bad_key_id, bad_key_arn = bad_key["KeyId"], bad_key["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: kms.schedule_key_deletion(KeyId=bad_key_id, PendingWindowInDays=7)))

    ctx.on_cleanup(lambda: _safe(lambda: cw.disassociate_dataset_kms_key(DatasetIdentifier="default")))

    # Establish a known-good association. This is the documented "rotate the key" path
    # and must succeed (retry briefly for IAM/KMS policy propagation latency).
    _retry(
        lambda: cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=good_key_arn),
        attempts=6,
        delay_s=5.0,
    )
    current = cw.get_dataset(DatasetIdentifier="default")
    assert current.get("KmsKeyArn") == good_key_arn, (
        f"expected dataset to be associated with {good_key_arn}, got {current.get('KmsKeyArn')!r}"
    )

    # Now attempt to associate a key whose policy does not grant CloudWatch permission.
    code, message = _refusal(
        lambda: cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=bad_key_arn)
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r} ({message!r})"
    assert message == (
        f"Unable to validate KMS key {bad_key_arn}. Verify the key exists and the key policy "
        "grants kms:DescribeKey to the CloudWatch service principal."
    ), (
        f"unexpected AccessDenied message {message!r}"
    )

    # The rejected call must not have silently overwritten (or cleared) the working association.
    after = cw.get_dataset(DatasetIdentifier="default")
    assert after.get("KmsKeyArn") == good_key_arn, (
        f"dataset KMS key association was mutated by a rejected call: now {after.get('KmsKeyArn')!r}"
    )


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


def _refusal(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) of the refusal. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _retry(fn: Callable[[], Any], *, attempts: int, delay_s: float) -> Any:
    last_exc: Exception | None = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - transient KMS/IAM propagation
            last_exc = exc
            if i < attempts - 1:
                time.sleep(delay_s)
    if last_exc is not None:
        raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
