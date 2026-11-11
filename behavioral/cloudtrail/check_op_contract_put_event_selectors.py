"""op-contract-put-event-selectors."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-put-event-selectors"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutEventSelectors persists the given selectors.

    Exceeding the 5-selector cap is rejected and leaves the stored selectors untouched.
    """
    ct = ctx.client("cloudtrail")
    bucket, _account_id = _create_trail_bucket(ctx)
    name = ctx.unique_name("sim2real-ct-trail-")
    _create_trail_retrying(
        ct, Name=name, S3BucketName=bucket, TagsList=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_trail(ct, name))

    selectors = [{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True, "DataResources": []}]
    resp = ct.put_event_selectors(TrailName=name, EventSelectors=selectors)
    # AWS echoes back each selector with defaults for fields not supplied (e.g. an empty
    # ExcludeManagementEventSources list), so compare against the fully-populated form.
    expected = [{**selectors[0], "ExcludeManagementEventSources": []}]
    assert resp["EventSelectors"] == expected, resp["EventSelectors"]
    assert resp["TrailARN"].endswith(f"trail/{name}"), resp["TrailARN"]

    persisted = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert persisted == expected, persisted

    # Error boundary: a trail supports at most 5 event selectors; providing 6 is rejected and
    # the previously-persisted (1-selector) configuration is left unchanged.
    too_many = [
        {"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True, "DataResources": []}
        for _ in range(6)
    ]
    code, message = _error(lambda: ct.put_event_selectors(TrailName=name, EventSelectors=too_many))
    assert code == "InvalidEventSelectorsException", code
    assert message == "Specify a valid number of selectors (1 to 5) for your trail", message

    unchanged = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert unchanged == expected, unchanged


def _error(fn):
    """Call fn() and return its (Error.Code, Error.Message); raise if the call succeeds."""
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
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
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
