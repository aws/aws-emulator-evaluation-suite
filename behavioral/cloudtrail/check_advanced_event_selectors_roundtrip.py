"""advanced-event-selectors-roundtrip."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


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


def _create_bucket_only(s3, bucket, region):
    """Create a plain S3 bucket (no CloudTrail policy)."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        # S3's own API quirk, not a pin of this check's region: CreateBucketConfiguration
        # must be omitted for us-east-1 and is required everywhere else.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
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


def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_trail(ct, name):
    """Best-effort teardown: stop logging (if on) then delete the trail."""
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        _call(lambda: ct.delete_trail(Name=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _trail_arn(ctx, name):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cloudtrail:{ctx.region}:{account}:trail/{name}"


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail (provisioning a policy-ready bucket unless S3BucketName is
    given) and register best-effort teardown of the trail and any bucket made."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {"Name": name, "S3BucketName": bucket}
    params.update(kwargs)
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


CHECK = "advanced-event-selectors-roundtrip"
GROUP = 'trail-config'
SERVICES = ['cloudtrail']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutEventSelectors with AdvancedEventSelectors persists them and clears the basic form."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    _create_trail(ctx, ct, s3, name)

    # Before state: a freshly created trail defaults to the basic (classic) selector
    # form, not the advanced one — so there is a basic form to clear.
    before = ct.get_event_selectors(TrailName=name)
    assert "AdvancedEventSelectors" not in before, (
        f"expected no AdvancedEventSelectors on a fresh trail, got {before.get('AdvancedEventSelectors')}"
    )
    assert "EventSelectors" in before, f"expected a default basic EventSelectors, got {before}"

    advanced = [
        {
            "Name": "log-write-management-events",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Management"]},
                {"Field": "readOnly", "Equals": ["false"]},
            ],
        }
    ]
    put_resp = _call(
        lambda: ct.put_event_selectors(
            TrailName=name, AdvancedEventSelectors=advanced
        )
    )
    expected_arn = _trail_arn(ctx, name)
    assert put_resp["TrailARN"] == expected_arn, (
        f"expected TrailARN {expected_arn}, got {put_resp['TrailARN']}"
    )
    assert put_resp["AdvancedEventSelectors"][0]["Name"] == (
        "log-write-management-events"
    ), f"expected echoed selector name 'log-write-management-events', got {put_resp['AdvancedEventSelectors'][0].get('Name')}"
    # The two representations are mutually exclusive in the response.
    assert "EventSelectors" not in put_resp, put_resp.get("EventSelectors")

    got = ct.get_event_selectors(TrailName=name)
    assert "EventSelectors" not in got, got.get("EventSelectors")
    sel = got["AdvancedEventSelectors"]
    assert len(sel) == 1, sel
    assert sel[0]["Name"] == "log-write-management-events", (
        f"expected persisted selector name 'log-write-management-events', got {sel[0].get('Name')}"
    )
    fields = {f["Field"]: f.get("Equals") for f in sel[0]["FieldSelectors"]}
    assert fields["eventCategory"] == ["Management"], (
        f"expected eventCategory Equals ['Management'], got {fields['eventCategory']}"
    )
    assert fields["readOnly"] == ["false"], (
        f"expected readOnly Equals ['false'], got {fields['readOnly']}"
    )

    # GetTrail must now report a custom selector configuration.
    trail = ct.get_trail(Name=name)["Trail"]
    assert trail["HasCustomEventSelectors"] is True, (
        f"expected HasCustomEventSelectors True after advanced put, got {trail.get('HasCustomEventSelectors')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
