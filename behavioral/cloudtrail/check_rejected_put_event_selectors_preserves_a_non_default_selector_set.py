"""rejected-put-event-selectors-preserves-a-non-default-selector-set."""

from __future__ import annotations

import copy
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rejected-put-event-selectors-preserves-a-non-default-selector-set"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']

# The exact default selector set a new trail carries, all four members.
_DEFAULT_SELECTORS = [{
    "ReadWriteType": "All",
    "IncludeManagementEvents": True,
    "DataResources": [],
    "ExcludeManagementEventSources": [],
}]


def _call(fn, retry_codes=(
    "ThrottlingException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
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
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)


def _trail_delivery_policy(bucket, account_id):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AWSCloudTrailAclCheck", "Effect": "Allow",
             "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket}"},
            {"Sid": "AWSCloudTrailWrite", "Effect": "Allow",
             "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject",
             "Resource": [f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                          f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*"],
             "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
        ],
    })


def _purge_bucket_once(s3, bucket):
    for pname, list_key, id_key in (("list_objects_v2", "Contents", None),
                                    ("list_object_versions", "Versions", "VersionId"),
                                    ("list_object_versions", "DeleteMarkers", "VersionId")):
        try:
            for page in s3.get_paginator(pname).paginate(Bucket=bucket):
                entries = page.get(list_key, [])
                if not entries:
                    continue
                objects = []
                for entry in entries:
                    item = {"Key": entry["Key"]}
                    if id_key and entry.get(id_key):
                        item["VersionId"] = entry[id_key]
                    objects.append(item)
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
            continue


def _drain_and_delete_bucket(s3, bucket, *, attempts=6, delay_s=10.0):
    """Empty and delete the bucket, retrying, and RAISE on a deadline miss so a leaked billable
    bucket is visible rather than silent."""
    last = None
    for attempt in range(attempts):
        _purge_bucket_once(s3, bucket)
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchBucket":
                return
            last = exc
            if attempt < attempts - 1:
                time.sleep(delay_s)
    raise AssertionError(
        f"could not delete bucket {bucket} after {attempts} attempts; a billable S3 bucket has "
        f"been leaked. Last error: {last}"
    )


def _delete_trail(ct, name):
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


def _error_code(fn):
    """Return the AWS error code and message; raise if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError("PutEventSelectors unexpectedly SUCCEEDED on an invalid selector list")


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Three differently invalid PutEventSelectors calls each fail with InvalidEventSelectorsException
    and leave a non-default selector set exactly as applied, never reset to the default, which
    would silently widen logging and billing.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PutEventSelectors.html
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-ct-selb-").lower()
    _create_bucket_only(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]})
    s3.put_bucket_policy(Bucket=bucket, Policy=_trail_delivery_policy(bucket, account))

    name = ctx.unique_name("sim2real-behav-ct-trail-")
    _call(lambda: ct.create_trail(Name=name, S3BucketName=bucket))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))

    # A non-default baseline, so a reset-to-default on rejection is distinguishable from no change.
    on_disk_default = _call(lambda: ct.get_event_selectors(TrailName=name))["EventSelectors"]
    assert on_disk_default == _DEFAULT_SELECTORS, (
        f"the measured default selector set has drifted: a new trail reports "
        f"{on_disk_default!r}, expected {_DEFAULT_SELECTORS!r}. The rest of this check compares "
        f"against that default, so it cannot proceed on a different one."
    )
    wanted = [{"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True}]
    echoed = _call(lambda: ct.put_event_selectors(
        TrailName=name, EventSelectors=copy.deepcopy(wanted)))["EventSelectors"]
    baseline = _call(lambda: ct.get_event_selectors(TrailName=name))["EventSelectors"]
    assert baseline == echoed, (
        f"PutEventSelectors echoed {echoed!r} but GetEventSelectors reports {baseline!r}; the "
        f"baseline is not trustworthy and neither is anything compared against it"
    )
    assert baseline != _DEFAULT_SELECTORS, (
        f"the baseline the rejections are measured against is indistinguishable from the "
        f"default {_DEFAULT_SELECTORS!r}; a reset-on-rejection target would be invisible. Got "
        f"{baseline!r}"
    )
    assert baseline[0]["ReadWriteType"] == "ReadOnly", (
        f"the non-default baseline did not take effect: {baseline!r}"
    )

    invalid_payloads = {
        "six-element selector list": [
            {"ReadWriteType": "All", "IncludeManagementEvents": True} for _ in range(6)],
        "unknown DataResources type": [
            {"ReadWriteType": "All", "IncludeManagementEvents": True,
             "DataResources": [{"Type": "AWS::Nope::Nope",
                                "Values": [f"arn:aws:s3:::{bucket}/"]}]}],
        "unknown ReadWriteType": [
            {"ReadWriteType": "Sideways", "IncludeManagementEvents": True}],
    }
    expected_messages = {
        "six-element selector list": "Specify a valid number of selectors (1 to 5) for your trail",
        "unknown DataResources type": "Value AWS::Nope::Nope for DataResources.Type is invalid.",
        "unknown ReadWriteType": "Value Sideways for ReadWriteType is invalid.",
    }
    # Three distinct validation paths: one rejection plus an unchanged read is also consistent
    # with the call being ignored, and a reset may happen on only one path.
    for label, payload in invalid_payloads.items():
        code, message = _error_code(lambda p=payload: ct.put_event_selectors(
            TrailName=name, EventSelectors=copy.deepcopy(p)))
        assert code == "InvalidEventSelectorsException", (
            f"expected InvalidEventSelectorsException for the {label}, got {code!r}"
        )
        assert message == expected_messages[label], (
            f"expected the {label} rejection message, got {message!r}"
        )
        after = _call(lambda: ct.get_event_selectors(TrailName=name))["EventSelectors"]
        assert after == baseline, (
            f"the rejected write ({label}) changed the live configuration: "
            f"baseline={baseline!r} after={after!r}"
        )
        assert after != _DEFAULT_SELECTORS, (
            f"the rejected write ({label}) RESET the trail to its default selectors "
            f"{_DEFAULT_SELECTORS!r}. This is the failure mode the shipped "
            f"check_put_event_selectors_invalid_fails.py:165-166 cannot detect, because it "
            f"compares the post-rejection state against the default. A trail reverted from "
            f"ReadOnly to All collects and bills every read event in the account."
        )
        assert after[0]["ReadWriteType"] == "ReadOnly", (
            f"the baseline ReadWriteType was lost after the {label} was rejected: {after!r}"
        )

    # HasCustomEventSelectors must still be true: a target that resets the selectors would also
    # flip this flag back, and consumers read it to decide whether to display a custom config.
    trail = _call(lambda: ct.get_trail(Name=name))["Trail"]
    assert trail.get("HasCustomEventSelectors") is True, (
        f"after three rejected writes over a custom selector set, GetTrail reports "
        f"HasCustomEventSelectors={trail.get('HasCustomEventSelectors')!r}: {trail!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
