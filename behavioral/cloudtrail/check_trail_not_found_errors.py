"""trail-not-found-errors."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. A success
    raises: a target that accepts what AWS refuses must fail loudly, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_trail_ignore(ct, name):
    try:
        ct.delete_trail(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


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


def _create_trail_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-ct-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(_bucket_policy(bucket, account_id)))

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_trail_retrying(ct, **kwargs):
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


CHECK = "trail-not-found-errors"
GROUP = 'error-semantics'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTrail, GetTrailStatus, GetEventSelectors and DeleteTrail succeed on a real trail and each raise
    TrailNotFoundException with "Unknown trail: ... for the user: <account>" for a never-created name."""
    ct = ctx.client("cloudtrail")
    bucket = _create_trail_bucket(ctx)
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    bogus = ctx.unique_name("sim2real-behav-ct-nonexistent-")
    _create_trail_retrying(ct, Name=name, S3BucketName=bucket)
    ctx.on_cleanup(lambda: _delete_trail_ignore(ct, name))

    # Positive control: each read succeeds against the real trail.
    real = ct.get_trail(Name=name)["Trail"]
    assert real["Name"] == name, real
    status = ct.get_trail_status(Name=name)
    assert status["IsLogging"] is False, status
    selectors = ct.get_event_selectors(TrailName=name)
    assert selectors["TrailARN"].endswith(f"trail/{name}"), selectors

    account = ctx.client("sts").get_caller_identity()["Account"]
    # GetTrail echoes the name as given; the other three operations echo the trail ARN.
    bogus_arn_message = (
        f"Unknown trail: arn:aws:cloudtrail:{ctx.region}:{account}:trail/{bogus} "
        f"for the user: {account}"
    )

    # Negative: the identical calls against a name that was never created are rejected.
    got = _error(lambda: ct.get_trail(Name=bogus))
    assert got == ("TrailNotFoundException", f"Unknown trail: {bogus} for the user: {account}"), got
    got = _error(lambda: ct.get_trail_status(Name=bogus))
    assert got == ("TrailNotFoundException", bogus_arn_message), got
    got = _error(lambda: ct.get_event_selectors(TrailName=bogus))
    assert got == ("TrailNotFoundException", bogus_arn_message), got

    # DeleteTrail's positive control is the delete of the real trail succeeding; the negative
    # below targets the still-never-created bogus name.
    ct.delete_trail(Name=name)
    remaining = ct.list_trails()["Trails"]
    assert all(t["Name"] != name for t in remaining), remaining
    got = _error(lambda: ct.delete_trail(Name=bogus))
    assert got == ("TrailNotFoundException", bogus_arn_message), got


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
