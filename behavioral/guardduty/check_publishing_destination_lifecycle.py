"""publishing-destination-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publishing-destination-lifecycle"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreatePublishingDestination publishes; UpdatePublishingDestination changes the KMS key
    used for encryption; DeletePublishingDestination removes it."""
    gd = ctx.client("guardduty")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    detector_id, _ = _get_or_create_detector(ctx)
    detector_arn = f"arn:aws:guardduty:{ctx.region}:{account_id}:detector/{detector_id}"

    bucket = _create_bucket_with_guardduty_policy(ctx, account_id, detector_arn)
    key_arn_1 = _create_guardduty_kms_key(ctx, account_id, detector_arn)

    resp = gd.create_publishing_destination(
        DetectorId=detector_id,
        DestinationType="S3",
        DestinationProperties={
            "DestinationArn": f"arn:aws:s3:::{bucket}",
            "KmsKeyArn": key_arn_1,
        },
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    destination_id = resp["DestinationId"]
    ctx.on_cleanup(lambda: _safe_delete_destination(gd, detector_id, destination_id))

    status = _poll_until(
        lambda: gd.describe_publishing_destination(
            DetectorId=detector_id, DestinationId=destination_id
        )["Status"],
        lambda s: s in ("PUBLISHING", "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY"),
        timeout_s=180,
        interval_s=10,
    )
    assert status == "PUBLISHING", f"expected PUBLISHING, got {status}"

    key_arn_2 = _create_guardduty_kms_key(ctx, account_id, detector_arn)
    gd.update_publishing_destination(
        DetectorId=detector_id,
        DestinationId=destination_id,
        DestinationProperties={
            "DestinationArn": f"arn:aws:s3:::{bucket}",
            "KmsKeyArn": key_arn_2,
        },
    )

    def _describe():
        return gd.describe_publishing_destination(
            DetectorId=detector_id, DestinationId=destination_id
        )

    updated = _poll_until(
        _describe,
        lambda d: d["DestinationProperties"]["KmsKeyArn"] == key_arn_2
        and d["Status"] == "PUBLISHING",
        timeout_s=180,
        interval_s=10,
    )
    updated_key_arn = updated["DestinationProperties"]["KmsKeyArn"]
    assert updated_key_arn == key_arn_2, f"expected KmsKeyArn {key_arn_2}, got {updated_key_arn}"

    gd.delete_publishing_destination(DetectorId=detector_id, DestinationId=destination_id)

    err = _wait_for_error(_describe, timeout_s=60, interval_s=5)
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err}"
    expected_describe = (
        "The request is rejected because the one or more input parameters have invalid values."
    )
    assert err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {err['Message']!r}"
    )

    try:
        gd.update_publishing_destination(
            DetectorId=detector_id,
            DestinationId=destination_id,
            DestinationProperties={
                "DestinationArn": f"arn:aws:s3:::{bucket}",
                "KmsKeyArn": key_arn_2,
            },
        )
        raise AssertionError("update_publishing_destination on a deleted destination succeeded")
    except ClientError as e:
        mutate_code = e.response["Error"]["Code"]
        assert mutate_code == "BadRequestException", (
            f"expected BadRequestException mutating a deleted destination, got {mutate_code}"
        )
        expected_mutate = (
            "The request failed because no publishingDestination exists with the provided "
            "publishingDestinationId."
        )
        mutate_message = e.response["Error"].get("Message")
        assert mutate_message == expected_mutate, (
            f"expected message {expected_mutate!r}, got {mutate_message!r}"
        )


# ===== helpers =====


def _get_or_create_detector(ctx):
    gd = ctx.client("guardduty")
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    resp = gd.create_detector(
        Enable=True, Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    )
    detector_id = resp["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id, True


def _create_bucket_with_guardduty_policy(ctx, account_id, detector_arn):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-gd-pubdest-")
    # us-east-1 is CreateBucket's own default region; passing a LocationConstraint
    # for it is rejected with InvalidLocationConstraint, so it must be omitted only there.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]},
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetBucketLocation",
                "Effect": "Allow",
                "Principal": {"Service": "guardduty.amazonaws.com"},
                "Action": "s3:GetBucketLocation",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "aws:SourceArn": detector_arn,
                    }
                },
            },
            {
                "Sid": "AllowPutObject",
                "Effect": "Allow",
                "Principal": {"Service": "guardduty.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "aws:SourceArn": detector_arn,
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_guardduty_kms_key(ctx, account_id, detector_arn):
    kms = ctx.client("kms")
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
                "Sid": "AllowGuardDutyKey",
                "Effect": "Allow",
                "Principal": {"Service": "guardduty.amazonaws.com"},
                "Action": "kms:GenerateDataKey",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "aws:SourceArn": detector_arn,
                    }
                },
            },
        ],
    }
    resp = kms.create_key(
        Description="sim2real guardduty publishing destination test key",
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    return resp["KeyMetadata"]["Arn"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _wait_for_error(call, *, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            call()
        except ClientError as e:
            return e.response["Error"]
        time.sleep(interval_s)
    raise AssertionError(f"call never failed within {timeout_s}s")


def _safe_delete_destination(gd, detector_id, destination_id):
    try:
        gd.delete_publishing_destination(DetectorId=detector_id, DestinationId=destination_id)
    except ClientError as exc:
        # GuardDuty reports a publishing destination that is already gone as BadRequestException.
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
