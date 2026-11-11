"""op-contract-describe-trails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describe-trails"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTrails returns the exact trail attributes; a malformed trail ARN matches nothing."""
    ct = ctx.client("cloudtrail")
    bucket, _account_id = _create_trail_bucket(ctx)
    name = ctx.unique_name("sim2real-ct-trail-")
    _create_trail_retrying(
        ct,
        Name=name,
        S3BucketName=bucket,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": name}],
    )
    ctx.on_cleanup(lambda: _delete_trail(ct, name))

    scoped = ct.describe_trails(trailNameList=[name])["trailList"]
    assert len(scoped) == 1, f"expected exactly 1 trail scoped to {name!r}, got {scoped!r}"
    trail = scoped[0]
    assert trail["Name"] == name, f"expected Name {name!r}, got {trail['Name']!r}"
    assert trail["S3BucketName"] == bucket, (
        f"expected S3BucketName {bucket!r}, got {trail['S3BucketName']!r}"
    )
    assert trail["IncludeGlobalServiceEvents"] is False, (
        f"expected IncludeGlobalServiceEvents False, got {trail['IncludeGlobalServiceEvents']!r}"
    )
    assert trail["HomeRegion"] == ctx.region, (
        f"expected HomeRegion {ctx.region!r}, got {trail['HomeRegion']!r}"
    )

    all_trails = ct.describe_trails()["trailList"]
    assert any(t["Name"] == name for t in all_trails), (
        f"expected {name!r} in unfiltered describe_trails(), got names "
        f"{[t['Name'] for t in all_trails]!r}"
    )

    # Error boundary: a malformed CloudTrail ARN in trailNameList does not resolve to any
    # trail (it does not raise; it is simply filtered out of the result set), distinct from
    # a syntactically valid trail name/ARN.
    filtered = ct.describe_trails(trailNameList=["arn:aws:cloudtrail:bad"])["trailList"]
    assert filtered == [], f"expected malformed ARN to filter to [], got {filtered!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _bucket_policy(bucket: str, account_id: str) -> dict:
    return {
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
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }


def _create_trail_bucket(ctx):
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-ct-").lower().replace("_", "-")
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(_bucket_policy(bucket, account_id)))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]}
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket, account_id


def _create_trail_retrying(ct, **kwargs):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(6):
        try:
            return ct.create_trail(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InsufficientS3BucketPolicyException":
                raise
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _delete_trail(ct, name):
    from botocore.exceptions import ClientError

    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        ct.delete_trail(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
