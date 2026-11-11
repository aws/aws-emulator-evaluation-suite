"""put-event-selectors-invalid-fails."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    so an emulator accepting a call AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
    """Create a plain S3 bucket (no CloudTrail policy). us-east-1 rejects an explicit
    LocationConstraint on CreateBucket; every other region requires one -- an S3 quirk, not a
    region pin on this check's own resource."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs, tagged with the
    check id."""
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"},
    ]})


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
    """Teardown: stop logging (if on) then delete the trail; TrailNotFoundException is gone."""
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


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail (provisioning a policy-ready, tagged bucket unless S3BucketName is
    given) and register teardown of the trail and any bucket made."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {
        "Name": name,
        "S3BucketName": bucket,
        "TagsList": [
            {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"},
        ],
    }
    params.update(kwargs)
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


CHECK = "put-event-selectors-invalid-fails"
GROUP = 'error-semantics'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutEventSelectors answers InvalidEventSelectorsException with AWS's exact message for 6 selectors, for
    IncludeManagementEvents false with no DataResources, and for EventSelectors plus AdvancedEventSelectors;
    after each refusal GetEventSelectors still returns the non-default WriteOnly baseline."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    _create_trail(ctx, ct, s3, name)

    # Positive control: apply a distinctive NON-DEFAULT selector set and read it back, so the
    # negatives below have state to prove untouched that isn't indistinguishable from a reset.
    wanted = [{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}]
    echoed = _call(
        lambda: ct.put_event_selectors(TrailName=name, EventSelectors=wanted)
    )["EventSelectors"]
    baseline = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert baseline == echoed, f"PutEventSelectors echoed {echoed!r} but GetEventSelectors reports {baseline!r}"
    assert baseline[0]["ReadWriteType"] == "WriteOnly", (
        f"the non-default baseline did not take effect: {baseline!r}"
    )

    too_many = [
        {"ReadWriteType": "All", "IncludeManagementEvents": True} for _ in range(6)
    ]
    code, message = _error(
        lambda: ct.put_event_selectors(TrailName=name, EventSelectors=too_many)
    )
    assert code == "InvalidEventSelectorsException", f"expected InvalidEventSelectorsException for a 6-element selector list, got {code!r}"
    assert message == "Specify a valid number of selectors (1 to 5) for your trail", message
    after = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert after == baseline, f"a rejected >5-selector write changed the live configuration: baseline={baseline!r} after={after!r}"

    # A selector that logs nothing at all (no management events, no data
    # resources) is rejected rather than accepted as a silent "log nothing".
    code, message = _error(
        lambda: ct.put_event_selectors(
            TrailName=name,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": False,
                    "DataResources": [],
                }
            ],
        )
    )
    assert code == "InvalidEventSelectorsException", f"expected InvalidEventSelectorsException for the empty selector combination, got {code!r}"
    assert message == (
        "Invalid combination of parameters in EventSelectors. When includeManagementEvents is "
        "false, DataResources must not be empty"
    ), message
    after = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert after == baseline, f"a rejected empty-combination write changed the live configuration: baseline={baseline!r} after={after!r}"

    # EventSelectors and AdvancedEventSelectors are mutually exclusive -- supplying both in one
    # call must be rejected, not silently merged or one arm silently preferred.
    code, message = _error(
        lambda: ct.put_event_selectors(
            TrailName=name,
            EventSelectors=[
                {"ReadWriteType": "All", "IncludeManagementEvents": True, "DataResources": []}
            ],
            AdvancedEventSelectors=[
                {
                    "Name": "mgmt-only",
                    "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}],
                }
            ],
        )
    )
    assert code == "InvalidEventSelectorsException", f"expected InvalidEventSelectorsException for mixing EventSelectors and AdvancedEventSelectors, got {code!r}"
    assert message == (
        "You can select events by using either EventSelectors or AdvancedEventSelectors, but "
        "not both."
    ), message
    after = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert after == baseline, f"a rejected basic+advanced write changed the live configuration: baseline={baseline!r} after={after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
