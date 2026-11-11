"""start-logging-revoked-bucket-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-logging-revoked-bucket-permission-denied"
GROUP = "negative-classes"
SERVICES = ["cloudtrail"]

# StartLogging performs no synchronous S3 permission validation (its Errors list has no
# InsufficientS3BucketPolicyException), so the revoked policy is detected via UpdateTrail, which
# re-validates the bucket policy synchronously; async log delivery would take minutes.


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartLogging still succeeds after a trail's bucket policy is revoked, but UpdateTrail on it
    is rejected with InsufficientS3BucketPolicyException and changes nothing.
    The identical UpdateTrail on a trail with an intact policy succeeds."""
    ct = ctx.client("cloudtrail")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    good_bucket, good_trail, good_arn = _create_trail(ctx, account_id)
    bad_bucket, bad_trail, bad_arn = _create_trail(ctx, account_id)

    # Revoke the policy outright: removing only the s3:PutObject statement does not trip
    # UpdateTrail's synchronous re-validation.
    s3 = ctx.client("s3")
    s3.delete_bucket_policy(Bucket=bad_bucket)

    # StartLogging succeeds for both trails regardless of bucket policy.
    ct.start_logging(Name=good_trail)
    ct.start_logging(Name=bad_trail)
    ctx.on_cleanup(lambda: _stop_logging_ignore(ct, good_trail))
    ctx.on_cleanup(lambda: _stop_logging_ignore(ct, bad_trail))
    assert ct.get_trail_status(Name=good_trail)["IsLogging"] is True
    assert ct.get_trail_status(Name=bad_trail)["IsLogging"] is True

    # S3KeyPrefix rides along so a wrongly-accepted update is observable below; re-designating
    # the same S3BucketName alone would be a no-op.
    update_err = _error(
        lambda: ct.update_trail(Name=bad_trail, S3BucketName=bad_bucket, S3KeyPrefix="denied-update")
    )
    assert update_err == ("InsufficientS3BucketPolicyException", f"Incorrect S3 bucket policy is detected for bucket: {bad_bucket}"), (
        f"expected InsufficientS3BucketPolicyException with its exact message, got {update_err}"
    )

    # Positive control: the identical call succeeds against the intact-policy trail.
    ct.update_trail(Name=good_trail, S3BucketName=good_bucket, S3KeyPrefix="accepted-update")
    good_after = ct.get_trail(Name=good_trail)["Trail"]
    assert good_after["S3BucketName"] == good_bucket
    assert good_after.get("S3KeyPrefix") == "accepted-update", good_after.get("S3KeyPrefix")

    # Effect absent: the rejected UpdateTrail changed nothing on the revoked-policy trail.
    bad_after = ct.get_trail(Name=bad_trail)["Trail"]
    assert bad_after["S3BucketName"] == bad_bucket
    assert bad_after.get("S3KeyPrefix") != "denied-update", bad_after.get("S3KeyPrefix")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _stop_logging_ignore(ct, name):
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise



def _delete_trail_ignore(ct, name):
    try:
        ct.delete_trail(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    if ctx.region == "us-east-1":
        # us-east-1 is S3's CreateBucket default region; passing a LocationConstraint
        # for it is itself rejected, so it's the one region literal that must stay bare.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _full_write_policy(bucket, trail_arn, account_id):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket}",
                    "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    # UpdateTrail re-validates the policy against the call's S3KeyPrefix, so the
                    # prefixed delivery path must be granted too.
                    "Resource": [
                        f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                        f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                    ],
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control",
                            "aws:SourceArn": trail_arn,
                        }
                    },
                },
            ],
        }
    )


def _acl_check_only_policy(bucket, trail_arn):
    # Same policy, minus the s3:PutObject grant -- CloudTrail can still see the bucket
    # exists but can no longer write log files to it.
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket}",
                    "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
                }
            ],
        }
    )


def _create_trail(ctx, account_id):
    """Create a bucket + fully-permissioned trail. Returns (bucket, trail_name, trail_arn)."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, "sim2real-ctstartlog-")
    name = ctx.unique_name("sim2real-ctstartlog-trail-")
    trail_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:trail/{name}"
    s3.put_bucket_policy(Bucket=bucket, Policy=_full_write_policy(bucket, trail_arn, account_id))

    # A fresh bucket policy is eventually consistent; CreateTrail may briefly reject it.
    deadline = time.monotonic() + 20.0
    last_exc = None
    created = False
    while time.monotonic() < deadline:
        try:
            ct.create_trail(
                Name=name,
                S3BucketName=bucket,
                TagsList=[{"Key": "sim2real", "Value": CHECK}],
            )
            created = True
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InsufficientS3BucketPolicyException":
                raise
            last_exc = exc
            time.sleep(2.0)
    if not created:
        raise last_exc
    ctx.on_cleanup(lambda: _delete_trail_ignore(ct, name))
    return bucket, name, trail_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
