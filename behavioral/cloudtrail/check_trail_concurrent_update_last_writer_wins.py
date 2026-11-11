"""trail-concurrent-update-last-writer-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trail-concurrent-update-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["cloudtrail"]
_CONFLICT_MESSAGE = (
    "CloudTrail can't complete your request because it conflicts with another request to modify the same resource. Try again later."
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateTrail calls setting distinct field tuples: at least one succeeds, any
    loser fails with ConflictException, and the final trail equals one successful racer's tuple,
    never a merge."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    trail_name = ctx.unique_name("sim2real-trail-cc-")
    bucket_name = ctx.unique_name("sim2real-trail-cc-bkt-").lower()
    trail_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:trail/{trail_name}"

    _create_bucket(ctx, s3, bucket_name)
    ctx.on_cleanup(lambda: _safe_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [
            {"Key": "sim2real", "Value": CHECK},
            {"Key": "sim2real:managed", "Value": "true"},
        ]},
    )
    _put_trail_bucket_policy(s3, bucket_name, trail_arn, account_id)

    # Bucket policies are eventually consistent: CreateTrail can briefly raise
    # InsufficientS3BucketPolicyException right after PutBucketPolicy.
    _poll_until(
        lambda: _try_create_trail(ct, trail_name, bucket_name),
        lambda ok: ok,
        timeout_s=_cap(ctx, 60.0),
        interval_s=3,
    )
    ctx.on_cleanup(lambda: _safe_delete_trail(ct, trail_name))

    # A new trail can briefly reject mutations; one successful update first means the racers
    # race only each other.
    _poll_until(
        lambda: _try_update(ct, trail_name, "warmup", False),
        lambda ok: ok,
        timeout_s=_cap(ctx, 60.0),
        interval_s=3,
    )

    n_racers = 5
    tuples = [(f"sim2real-racer-{i}", i % 2 == 0) for i in range(n_racers)]

    def _update(prefix: str, include_global: bool):
        try:
            ct.update_trail(
                Name=trail_name, S3KeyPrefix=prefix, IncludeGlobalServiceEvents=include_global
            )
            return ("ok", (prefix, include_global))
        except ClientError as e:
            err = e.response.get("Error", {})
            return ("err", (err.get("Code"), err.get("Message")))

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_update, prefix, flag) for prefix, flag in tuples]
        results = [f.result() for f in futures]

    assert len(results) == n_racers

    successes = [r[1] for r in results if r[0] == "ok"]
    failures = [r[1] for r in results if r[0] == "err"]

    # CloudTrail may reject an overlapping UpdateTrail with ConflictException or serialize it.
    assert len(successes) >= 1, f"expected at least one winner, got: {results}"
    for code, message in failures:
        assert code == "ConflictException", failures
        assert message == _CONFLICT_MESSAGE, (
            f"ConflictException message {message!r}, expected {_CONFLICT_MESSAGE!r}: {failures}"
        )

    final = ct.get_trail(Name=trail_name)["Trail"]
    final_tuple = (final["S3KeyPrefix"], final["IncludeGlobalServiceEvents"])
    assert final_tuple in successes, (
        f"final state {final_tuple} does not match any successful racer's tuple {successes} -- "
        "fields were merged/corrupted across concurrent writers"
    )


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _try_update(ct, trail_name: str, prefix: str, include_global: bool) -> bool:
    try:
        ct.update_trail(
            Name=trail_name, S3KeyPrefix=prefix, IncludeGlobalServiceEvents=include_global
        )
        return True
    except ClientError as e:
        # UpdateTrail re-validates the bucket policy too, which can lag PutBucketPolicy even
        # after CreateTrail succeeded.
        if e.response["Error"]["Code"] in (
            "ConflictException",
            "InsufficientS3BucketPolicyException",
        ):
            return False
        raise


def _try_create_trail(ct, trail_name: str, bucket_name: str) -> bool:
    try:
        ct.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IncludeGlobalServiceEvents=False,
            TagsList=[
                {"Key": "sim2real", "Value": CHECK},
                {"Key": "sim2real:managed", "Value": "true"},
            ],
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "InsufficientS3BucketPolicyException":
            return False
        raise


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )


def _put_trail_bucket_policy(s3, bucket_name: str, trail_arn: str, account_id: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                # UpdateTrail re-validates PutObject coverage for the current S3KeyPrefix and
                # each racer sets a different prefix, so grant the whole bucket.
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
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


def _safe_delete_bucket(s3, bucket_name: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket_name, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _safe_delete_trail(ct, trail_name: str) -> None:
    try:
        ct.delete_trail(Name=trail_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
