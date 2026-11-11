"""op-contract-get-insight-selectors."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-get-insight-selectors"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInsightSelectors returns exactly what was configured; an unconfigured trail is rejected."""
    ct = ctx.client("cloudtrail")
    bucket, _account_id = _create_trail_bucket(ctx)

    configured_name = ctx.unique_name("sim2real-ct-trail-")
    _create_trail_retrying(
        ct,
        Name=configured_name,
        S3BucketName=bucket,
        TagsList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_trail(ct, configured_name))
    # ApiCallRateInsight requires the trail to log write management events.
    ct.put_event_selectors(
        TrailName=configured_name,
        EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True, "DataResources": []}],
    )
    ct.put_insight_selectors(
        TrailName=configured_name, InsightSelectors=[{"InsightType": "ApiCallRateInsight"}]
    )

    # Enabling Insights is eventually consistent; the poll window stays inside the check's time
    # budget. AWS adds a default EventCategory to each returned selector, so compare InsightTypes.
    resp = _poll_until(
        lambda: ct.get_insight_selectors(TrailName=configured_name),
        lambda r: [s.get("InsightType") for s in r.get("InsightSelectors", [])]
        == ["ApiCallRateInsight"],
        attempts=18,
        delay=10.0,
    )
    assert [s.get("InsightType") for s in resp["InsightSelectors"]] == [
        "ApiCallRateInsight"
    ], resp["InsightSelectors"]
    assert resp["TrailARN"].endswith(f"trail/{configured_name}"), resp["TrailARN"]

    # Error boundary: a trail that never had insight selectors configured is rejected, distinct
    # from a not-found trail.
    unconfigured_name = ctx.unique_name("sim2real-ct-trail-")
    _create_trail_retrying(
        ct,
        Name=unconfigured_name,
        S3BucketName=bucket,
        TagsList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_trail(ct, unconfigured_name))

    code, message = _error(lambda: ct.get_insight_selectors(TrailName=unconfigured_name))
    assert code == "InsightNotEnabledException", code
    expected_message = (
        f"Trail arn:aws:cloudtrail:{ctx.region}:{ctx.account}:trail/{unconfigured_name} does not have Insights "
        "enabled. Edit the trail settings to enable Insights, and then try the operation again."
    )
    assert message == expected_message, message


def _poll_until(fn, predicate, attempts=10, delay=3.0):
    last = None
    for _ in range(attempts):
        last = fn()
        if predicate(last):
            return last
        time.sleep(delay)
    raise TimeoutError(f"predicate never satisfied after {attempts} attempts; last={last!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
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
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
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
