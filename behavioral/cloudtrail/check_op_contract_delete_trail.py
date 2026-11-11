"""op-contract-delete-trail."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-delete-trail"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTrail removes the trail (GetTrail then 404s); deleting it again is rejected."""
    ct = ctx.client("cloudtrail")
    bucket, _account_id = _create_trail_bucket(ctx)
    name = ctx.unique_name("sim2real-ct-trail-")
    _create_trail_retrying(
        ct, Name=name, S3BucketName=bucket,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )

    ct.delete_trail(Name=name)

    # Substantive state assertion: the trail is actually gone, not just "no error was raised".
    code, message = _error(lambda: ct.get_trail(Name=name))
    assert code == "TrailNotFoundException", code
    assert message == f"Unknown trail: {name} for the user: {ctx.account}", message

    remaining = ct.list_trails()["Trails"]
    assert all(t["Name"] != name for t in remaining), (
        f"deleted trail {name!r} still appears in ListTrails: {remaining!r}"
    )

    described = ct.describe_trails(trailNameList=[name])["trailList"]
    assert described == [], (
        f"DescribeTrails for deleted trail {name!r} was not empty: {described!r}"
    )

    # Error boundary: deleting an already-deleted (now nonexistent) trail is rejected.
    code2, message2 = _error(lambda: ct.delete_trail(Name=name))
    assert code2 == "TrailNotFoundException", code2
    expected2 = f"Unknown trail: arn:aws:cloudtrail:{ctx.region}:{ctx.account}:trail/{name} for the user: {ctx.account}"
    assert message2 == expected2, message2

    # The forbidden repeat-delete had no side effect: the trail is still (and remains) absent.
    still_absent = ct.list_trails()["Trails"]
    assert all(t["Name"] != name for t in still_absent), (
        f"the rejected repeat DeleteTrail left {name!r} visible in ListTrails: {still_absent!r}"
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(_bucket_policy(bucket, account_id)))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
