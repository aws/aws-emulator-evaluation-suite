"""update-trail-success-contract."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "update-trail-success-contract"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTrail mutates the requested fields and GetTrail/DescribeTrails reflect the change."""
    # CreateTrail is given S3KeyPrefix="initial-prefix" below, so CloudTrail's log-delivery
    # test writes land under "initial-prefix/AWSLogs/<account>/..." rather than directly
    # under "AWSLogs/<account>/...". The bucket policy's write-permission Resource must
    # include that same prefix or every CreateTrail call fails permanently with
    # InsufficientS3BucketPolicyException (no amount of retrying fixes a policy that
    # simply doesn't cover the path CloudTrail actually writes to).
    bucket = _create_trail_bucket(ctx, prefix="initial-prefix")
    ct = ctx.client("cloudtrail")
    trail_name = ctx.unique_name("sim2real-ct-trail-")

    create_resp = _create_trail_with_retry(
        ct,
        Name=trail_name,
        S3BucketName=bucket,
        S3KeyPrefix="initial-prefix",
        IncludeGlobalServiceEvents=True,
        IsMultiRegionTrail=False,
        EnableLogFileValidation=False,
        TagsList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_name))
    trail_arn = create_resp["TrailARN"]
    assert create_resp["S3KeyPrefix"] == "initial-prefix", create_resp.get("S3KeyPrefix")
    assert create_resp["LogFileValidationEnabled"] is False, create_resp.get("LogFileValidationEnabled")
    assert create_resp["IncludeGlobalServiceEvents"] is True, create_resp.get("IncludeGlobalServiceEvents")

    # Sanity: GetTrail right after create reflects the initial values.
    before = ct.get_trail(Name=trail_name)["Trail"]
    assert before["S3KeyPrefix"] == "initial-prefix", before.get("S3KeyPrefix")
    assert before["LogFileValidationEnabled"] is False, before.get("LogFileValidationEnabled")

    update_resp = ct.update_trail(
        Name=trail_name,
        S3KeyPrefix="updated-prefix",
        IncludeGlobalServiceEvents=False,
        EnableLogFileValidation=True,
    )

    # UpdateTrail's own response reflects every field it just changed.
    assert update_resp["Name"] == trail_name, update_resp.get("Name")
    assert update_resp["TrailARN"] == trail_arn, update_resp.get("TrailARN")
    assert update_resp["S3KeyPrefix"] == "updated-prefix", update_resp.get("S3KeyPrefix")
    assert update_resp["IncludeGlobalServiceEvents"] is False, update_resp.get("IncludeGlobalServiceEvents")
    assert update_resp["LogFileValidationEnabled"] is True, update_resp.get("LogFileValidationEnabled")
    assert update_resp["S3BucketName"] == bucket, update_resp.get("S3BucketName")

    # The mutation is durable: a fresh GetTrail call sees the same updated values.
    after = ct.get_trail(Name=trail_name)["Trail"]
    assert after["S3KeyPrefix"] == "updated-prefix", after.get("S3KeyPrefix")
    assert after["IncludeGlobalServiceEvents"] is False, after.get("IncludeGlobalServiceEvents")
    assert after["LogFileValidationEnabled"] is True, after.get("LogFileValidationEnabled")
    assert after["S3BucketName"] == bucket, after.get("S3BucketName")
    assert after["TrailARN"] == trail_arn, after.get("TrailARN")

    # DescribeTrails (the bulk/list read path) agrees with the single-trail read path.
    described = ct.describe_trails(trailNameList=[trail_name])["trailList"]
    assert len(described) == 1, f"expected exactly 1 DescribeTrails entry, got {len(described)}"
    assert described[0]["S3KeyPrefix"] == "updated-prefix", described[0].get("S3KeyPrefix")
    assert described[0]["IncludeGlobalServiceEvents"] is False, described[0].get("IncludeGlobalServiceEvents")
    assert described[0]["LogFileValidationEnabled"] is True, described[0].get("LogFileValidationEnabled")


def _create_trail_bucket(ctx, prefix: str | None = None) -> str:
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-ct-bucket-")
    # Not a region pin on the bucket itself: S3's CreateBucket rejects a
    # LocationConstraint that names us-east-1 explicitly, so it must be omitted
    # (and only then) regardless of which region ctx.region actually is.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    # New buckets default to Object Ownership "BucketOwnerEnforced" (ACLs disabled)
    # since April 2023. CreateTrail's bucket-policy validation performs a real test
    # write using the "bucket-owner-full-control" canned ACL header required by the
    # policy below; with ACLs disabled that write is rejected and CreateTrail reports
    # it as InsufficientS3BucketPolicyException. Explicitly re-enable ACL support so
    # the policy's s3:x-amz-acl condition can actually be satisfied.
    s3.put_bucket_ownership_controls(
        Bucket=bucket,
        OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]},
    )

    def _cleanup_bucket() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)

    # CloudTrail's PutObject test write (and all real log delivery) lands under
    # "<prefix>/AWSLogs/<account>/..." when an S3KeyPrefix is configured. UpdateTrail
    # performs the same bucket-policy validation as CreateTrail, and this check
    # changes S3KeyPrefix after creation, so the write statement's Resource must cover
    # every prefix the trail could ever use (not just the one active at CreateTrail
    # time) or the later UpdateTrail call fails with InsufficientS3BucketPolicyException
    # even though the trail/bucket setup is otherwise correct.
    write_resource = f"arn:aws:s3:::{bucket}/*"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": write_resource,
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _create_trail_with_retry(ct, timeout: float = 60.0, interval: float = 3.0, **kwargs) -> dict[str, Any]:
    """CreateTrail validates the S3 bucket policy against a read that can lag shortly
    after PutBucketPolicy (S3 policy propagation is eventually consistent), so a freshly
    written policy can transiently be reported as insufficient. Poll through that window."""
    from botocore.exceptions import ClientError

    deadline = time.time() + timeout
    while True:
        try:
            return ct.create_trail(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientS3BucketPolicyException":
                raise
            if time.time() >= deadline:
                raise
            time.sleep(interval)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
