"""op-contract-get-trail-status."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-get-trail-status"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTrailStatus reflects IsLogging toggled by StartLogging; a nonexistent trail is rejected."""
    ct = ctx.client("cloudtrail")
    bucket, _account_id = _create_trail_bucket(ctx)
    name = ctx.unique_name("sim2real-ct-trail-")
    _create_trail_retrying(ct, Name=name, S3BucketName=bucket)
    ctx.on_cleanup(lambda: _delete_trail(ct, name))

    initial = ct.get_trail_status(Name=name)
    assert initial["IsLogging"] is False, f"expected a fresh trail to report IsLogging=False, got {initial['IsLogging']!r}"

    ct.start_logging(Name=name)
    status = _poll_until(
        lambda: ct.get_trail_status(Name=name),
        lambda s: s["IsLogging"] is True,
        timeout_s=60.0,
    )
    assert status["IsLogging"] is True, f"expected IsLogging=True after StartLogging, got {status['IsLogging']!r}"
    assert "StartLoggingTime" in status, f"StartLoggingTime missing from GetTrailStatus after StartLogging: {sorted(status)}"

    # Error boundary: status for a nonexistent trail is rejected.
    code, message = _error(lambda: ct.get_trail_status(Name="sim2real-no-such-trail-555"))
    assert code == "TrailNotFoundException", f"expected TrailNotFoundException for a nonexistent trail, got {code!r}"
    expected_message = f"Unknown trail: arn:aws:cloudtrail:{ctx.region}:{ctx.account}:trail/sim2real-no-such-trail-555 for the user: {ctx.account}"
    assert message == expected_message, message


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last}")


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
