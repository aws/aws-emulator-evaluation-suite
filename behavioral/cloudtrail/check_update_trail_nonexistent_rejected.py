"""update-trail-nonexistent-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "update-trail-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTrail on a nonexistent Name is rejected with TrailNotFoundException and mutates
    nothing, while the identical call against a real trail (positive control) succeeds."""
    ct = ctx.client("cloudtrail")

    account = ctx.client("sts").get_caller_identity()["Account"]
    missing_name = ctx.unique_name("sim2real-ct-missing-trail-")
    code, message = _error(
        lambda: ct.update_trail(Name=missing_name, S3KeyPrefix="whatever")
    )
    assert code == "TrailNotFoundException", f"expected TrailNotFoundException, got {code}"
    # UpdateTrail names the trail by the ARN it derives from the Name; GetTrail echoes the Name.
    missing_arn = f"arn:aws:cloudtrail:{ctx.region}:{account}:trail/{missing_name}"
    expected = f"Unknown trail: {missing_arn} for the user: {account}"
    assert message == expected, f"expected UpdateTrail message {expected!r}, got {message!r}"

    # Effect absent: no trail by that name exists anywhere in the account/region.
    trails = ct.list_trails().get("Trails", [])
    assert all(t.get("Name") != missing_name for t in trails), (
        f"expected no trail named {missing_name!r} in list_trails, found one"
    )
    get_code, get_message = _error(lambda: ct.get_trail(Name=missing_name))
    assert get_code == "TrailNotFoundException", f"expected TrailNotFoundException, got {get_code}"
    expected = f"Unknown trail: {missing_name} for the user: {account}"
    assert get_message == expected, f"expected GetTrail message {expected!r}, got {get_message!r}"

    # Positive control: the exact same UpdateTrail call succeeds against a real trail.
    # CreateTrail is given S3KeyPrefix="orig-prefix", so CloudTrail's log-delivery test
    # writes land under "orig-prefix/AWSLogs/<account>/..."; the bucket policy's write
    # Resource must include that prefix or CreateTrail permanently fails with
    # InsufficientS3BucketPolicyException regardless of retries.
    bucket = _create_trail_bucket(ctx, prefix="orig-prefix")
    trail_name = ctx.unique_name("sim2real-ct-real-trail-")
    _create_trail_with_retry(ct, Name=trail_name, S3BucketName=bucket, S3KeyPrefix="orig-prefix")
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_name))

    ok_resp = ct.update_trail(Name=trail_name, S3KeyPrefix="whatever")
    assert ok_resp["Name"] == trail_name, f"expected Name {trail_name!r}, got {ok_resp['Name']!r}"
    assert ok_resp["S3KeyPrefix"] == "whatever", (
        f"expected S3KeyPrefix 'whatever', got {ok_resp['S3KeyPrefix']!r}"
    )

    # Terminal read is independent of the mutating UpdateTrail call itself: GetTrail
    # confirms the change actually stuck, not just that the response echoed it back.
    after = ct.get_trail(Name=trail_name)["Trail"]
    assert after["S3KeyPrefix"] == "whatever", (
        f"expected GetTrail to reflect S3KeyPrefix 'whatever', got {after['S3KeyPrefix']!r}"
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if it raised. An unexpected
    SUCCESS raises instead of returning a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_trail_bucket(ctx, prefix: str | None = None) -> str:
    import json

    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-ct-bucket-")
    # us-east-1 refuses an explicit LocationConstraint, so the bucket is created without one there.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

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
    # performs the same bucket-policy validation as CreateTrail, and this check's
    # positive control changes S3KeyPrefix after creation, so the write statement's
    # Resource must cover every prefix the trail could ever use (not just the one
    # active at CreateTrail time) or the later UpdateTrail call fails with
    # InsufficientS3BucketPolicyException even though the trail/bucket setup is
    # otherwise correct.
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
