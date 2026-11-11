"""associate-dataset-kms-key-nonexistent-key-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-dataset-kms-key-nonexistent-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey with a well-formed but nonexistent key ARN fails with AccessDenied
    "Unable to validate KMS key <arn>. Verify the key exists and ..." and leaves the dataset on the
    real key it associated first."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    dataset_arn = f"arn:aws:cloudwatch:{region}:{account_id}:dataset/default"

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

    ctx.on_cleanup(_restore)

    good_key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-good-key-"),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=good_key_id, PendingWindowInDays=7))
    good_key_arn = kms.describe_key(KeyId=good_key_id)["KeyMetadata"]["Arn"]
    kms.put_key_policy(
        KeyId=good_key_id,
        PolicyName="default",
        Policy=json.dumps(_cloudwatch_dataset_key_policy(account_id, dataset_arn)),
    )

    _accepted(
        lambda: cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=good_key_arn),
        retry_code="AccessDenied",
        timeout_s=60,
        interval_s=5,
    )
    assert cw.get_dataset(DatasetIdentifier="default")["KmsKeyArn"] == good_key_arn, (
        "positive control: a correctly-permissioned key must associate"
    )

    bogus_key_arn = (
        f"arn:aws:kms:{region}:{account_id}:key/00000000-0000-0000-0000-000000000000"
    )

    code, message = _refusal(
        lambda: cw.associate_dataset_kms_key(
            DatasetIdentifier="default", KmsKeyArn=bogus_key_arn
        )
    )
    assert code == "AccessDenied", (
        f"expected AccessDenied for a nonexistent KMS key, got {code} ({message!r})"
    )
    assert message == (
        f"Unable to validate KMS key {bogus_key_arn}. Verify the key exists and the key policy "
        "grants kms:DescribeKey to the CloudWatch service principal."
    ), (
        f"unexpected AccessDenied message {message!r}"
    )

    after = cw.get_dataset(DatasetIdentifier="default")
    assert after.get("KmsKeyArn") == good_key_arn, (
        "dataset encryption configuration changed despite a rejected AssociateDatasetKmsKey call"
    )


def _cloudwatch_dataset_key_policy(account_id: str, dataset_arn: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableIAMUserPermissions",
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
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": dataset_arn},
                },
            },
        ],
    }


def _refusal(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) of the refusal. An unexpected
    SUCCESS raises, so a target accepting a call AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _accepted(fn, *, retry_code, timeout_s, interval_s):
    """Call fn() until it succeeds, retrying only retry_code (key-policy propagation); any other
    refusal, or retry_code past the deadline, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != retry_code:
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
