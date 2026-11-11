"""associate-dataset-kms-key-disabled-key-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-dataset-kms-key-disabled-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """AssociateDatasetKmsKey with a disabled KMS key is rejected with AccessDenied, leaving the
    dataset unchanged; re-enabling the key lets the identical call succeed.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_AssociateDatasetKmsKey.html
    """
    kms = ctx.client("kms")
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableAccountRootPermissions",
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
    )
    key = kms.create_key(
        Policy=policy,
        Description=ctx.unique_name("sim2real-behav-cw-dataset-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    ctx.on_cleanup(lambda: _ignore_client_error(
        lambda: cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    ))

    baseline_kms_arn = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")

    kms.disable_key(KeyId=key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda state: state == "Disabled",
        timeout_s=30.0,
        interval_s=2.0,
    )

    # On unexpected success the disassociate cleanup unpins the account's single default dataset.
    code, message = _refusal(
        lambda: cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
    )
    assert code == "AccessDenied", (
        f"expected AccessDenied for a disabled KMS key, got {code} ({message!r})"
    )
    assert message == f"KMS key {key_arn} is disabled.", (
        f"unexpected AccessDenied message {message!r}"
    )

    after_reject = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")
    assert after_reject == baseline_kms_arn, (
        f"dataset encryption changed despite rejected association: "
        f"{baseline_kms_arn!r} -> {after_reject!r}"
    )

    kms.enable_key(KeyId=key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda state: state == "Enabled",
        timeout_s=30.0,
        interval_s=2.0,
    )

    _accepted(
        lambda: cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn),
        retry_code="AccessDenied",
        timeout_s=30.0,
        interval_s=3.0,
    )
    after_restore = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")
    assert after_restore == key_arn, (
        f"expected the identical call to succeed once the key was re-enabled, "
        f"dataset KmsKeyArn is {after_restore!r} not {key_arn!r}"
    )


def _refusal(fn):
    """Return (Error.Code, Error.Message) of the refusal fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _accepted(fn, *, retry_code, timeout_s, interval_s):
    """Call fn() until it succeeds, retrying only retry_code while key state propagates."""
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


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
