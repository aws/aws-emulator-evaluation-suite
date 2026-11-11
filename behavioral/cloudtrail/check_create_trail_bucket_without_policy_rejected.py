"""create-trail-bucket-without-policy-rejected."""

from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-trail-bucket-without-policy-rejected"
GROUP = "trail-lifecycle"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrail on a bucket without a CloudTrail policy fails InsufficientS3BucketPolicyException
    and creates nothing; after granting AWSCloudTrailAclCheck + AWSCloudTrailWrite scoped to this
    trail's ARN, the identical call succeeds."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    trail_name = ctx.unique_name("sim2real-behav-trail-")
    bucket_name = ctx.unique_name("sim2real-behav-trailbkt-").lower()
    trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"

    s3.create_bucket(
        Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))

    # --- 1. no policy at all: CreateTrail is rejected and creates nothing ----------------------
    code, message = _error(
        lambda: ct.create_trail(Name=trail_name, S3BucketName=bucket_name)
    )
    assert code == "InsufficientS3BucketPolicyException", (
        f"CreateTrail against an unpolicied bucket must raise InsufficientS3BucketPolicyException, "
        f"got {code!r}"
    )
    assert message == f"Incorrect S3 bucket policy is detected for bucket: {bucket_name}", (
        f"CreateTrail against the unpolicied bucket was refused with {message!r}"
    )
    existing = ct.describe_trails(trailNameList=[trail_name])["trailList"]
    assert existing == [], (
        f"a rejected CreateTrail must leave no trail behind; DescribeTrails reports {existing!r}"
    )

    # --- 2. grant the policy CloudTrail requires, then the identical call succeeds -------------
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": trail_arn,
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    created = ct.create_trail(Name=trail_name, S3BucketName=bucket_name)
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_name))
    assert created["Name"] == trail_name, (
        f"expected the retried CreateTrail to succeed and echo Name={trail_name!r}, got "
        f"{created['Name']!r}"
    )
    assert created["S3BucketName"] == bucket_name, (
        f"expected S3BucketName={bucket_name!r} on the created trail, got "
        f"{created['S3BucketName']!r}"
    )

    confirmed = ct.describe_trails(trailNameList=[trail_name])["trailList"]
    assert len(confirmed) == 1 and confirmed[0]["Name"] == trail_name, (
        f"DescribeTrails must now report exactly the one trail {trail_name!r}, got {confirmed!r}"
    )


def _empty_and_delete_bucket(s3, bucket_name: str) -> None:
    """CreateTrail writes a zero-byte AWSLogs/<account>/CloudTrail/ marker object as soon as the
    trail is created, even before StartLogging — so a bucket this check made is never actually
    empty, and a bare delete_bucket raises BucketNotEmpty."""
    resp = s3.list_object_versions(Bucket=bucket_name)
    objects = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("Versions", [])]
    objects += [
        {"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("DeleteMarkers", [])
    ]
    if objects:
        s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects})
    s3.delete_bucket(Bucket=bucket_name)


class _Unexpected(Exception):
    """The call that was expected to fail succeeded."""


def _error(fn) -> tuple[str, str]:
    """(code, message) of the AWS error fn raises. RAISES if fn succeeds — success is never a code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise _Unexpected(f"call was expected to fail but returned {str(result)[:300]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
