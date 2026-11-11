"""create-describe-delete-trail-lifecycle."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore (Error.Code, HTTP status, Error.Message). An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _call(fn, retry_codes=(
    "ThrottlingException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
    """Invoke fn(), retrying transient CloudTrail control-plane errors."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_bucket_only(s3, bucket, region):
    """Create a plain S3 bucket (no CloudTrail policy)."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        # S3 quirk, not a pinned resource region: us-east-1 rejects an explicit
        # LocationConstraint on create_bucket, every other region requires one.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "BucketAlreadyOwnedByYou":
            raise


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
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
                "Resource": [
                    f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                ],
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _tolerating(fn, code):
    """fn(), ignoring only the service's own not-found ``code``."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != code:
            raise


def _empty_and_delete_bucket(s3, bucket):
    def _empty():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                )

    _tolerating(_empty, "NoSuchBucket")
    _tolerating(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket")


def _delete_trail(ct, name):
    """Teardown: stop logging (if on) then delete the trail; only an already-gone trail is tolerated."""
    _tolerating(lambda: ct.stop_logging(Name=name), "TrailNotFoundException")
    _tolerating(lambda: _call(lambda: ct.delete_trail(Name=name)), "TrailNotFoundException")


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail (provisioning a policy-ready bucket unless S3BucketName is
    given) and register best-effort teardown of the trail and any bucket made."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {"Name": name, "S3BucketName": bucket, "TagsList": [{"Key": "sim2real-check", "Value": CHECK}]}
    params.update(kwargs)
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


CHECK = "create-describe-delete-trail-lifecycle"
GROUP = 'trail-lifecycle'
SERVICES = ['cloudtrail']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrail->GetTrail/DescribeTrails/ListTrails->DeleteTrail reflects the trail's existence."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    _create_trail(ctx, ct, s3, name)

    got = ct.get_trail(Name=name)
    assert got["Trail"]["Name"] == name, f"expected GetTrail Name {name!r}, got {got['Trail'].get('Name')!r}"
    expected_arn = f"arn:aws:cloudtrail:{ctx.region}:{ctx.account}:trail/{name}"
    assert got["Trail"].get("TrailARN") == expected_arn, (
        f"expected GetTrail TrailARN {expected_arn!r}, got {got['Trail'].get('TrailARN')!r}"
    )

    described = ct.describe_trails(trailNameList=[name])
    names = [t["Name"] for t in described["trailList"]]
    assert name in names, f"expected {name} in describe_trails output, got {names}"

    listed = ct.list_trails()
    arns = [t.get("Name") for t in listed.get("Trails", [])]
    assert name in arns, f"expected {name} in list_trails output, got {arns}"

    _call(lambda: ct.delete_trail(Name=name))

    def probe():
        return ct.list_trails().get("Trails", [])

    remaining = _poll_until(
        probe,
        lambda trails: name not in [t.get("Name") for t in trails],
        timeout_s=60,
        interval_s=3,
        description="deleted trail disappears from ListTrails",
    )
    assert name not in [t.get("Name") for t in remaining], f"{name} still present after delete: {remaining!r}"

    code, status, message = _error(lambda: ct.get_trail(Name=name))
    assert code == "TrailNotFoundException", f"expected TrailNotFoundException from GetTrail, got {code!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected an HTTP 4xx from GetTrail on the deleted trail, got {status!r}"
    expected_message = f"Unknown trail: {name} for the user: {ctx.account}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # A mutation on the now-dead id is rejected too, and has no side effect: the
    # trail stays absent from an independent read.
    code2, status2, message2 = _error(lambda: ct.delete_trail(Name=name))
    assert code2 == "TrailNotFoundException", f"expected TrailNotFoundException from repeat DeleteTrail, got {code2!r}"
    assert isinstance(status2, int) and 400 <= status2 < 500, f"expected an HTTP 4xx from repeat DeleteTrail, got {status2!r}"
    expected_message = f"Unknown trail: {expected_arn} for the user: {ctx.account}"
    assert message2 == expected_message, f"expected the message {expected_message!r}, got {message2!r}"
    post = [t.get("Name") for t in ct.list_trails().get("Trails", [])]
    assert name not in post, f"repeat delete had a side effect: {name} reappeared in ListTrails: {post!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
