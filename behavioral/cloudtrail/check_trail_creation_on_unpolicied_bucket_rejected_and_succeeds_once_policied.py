"""trail-creation-on-unpolicied-bucket-rejected-and-succeeds-once-policied."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trail-creation-on-unpolicied-bucket-rejected-and-succeeds-once-policied"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']


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
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        except ClientError:
            continue


def _drain_and_delete_bucket(s3, bucket, *, attempts=6, delay_s=10.0):
    """Empty and delete the bucket, retrying because CloudTrail may still be writing logs."""
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
    """Teardown: only TrailNotFoundException (already gone) is tolerated."""
    for op in (lambda: ct.stop_logging(Name=name), lambda: _call(lambda: ct.delete_trail(Name=name))):
        try:
            op()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
                raise


def _error_code(fn):
    """(Error.Code, HTTP status, Error.Message), raising if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError("call unexpectedly SUCCEEDED where a rejection was required")


def _paged_trail_names(ct):
    """Every trail name from DescribeTrails and the fully paginated ListTrails."""
    described = [t["Name"] for t in ct.describe_trails(includeShadowTrails=True)["trailList"]]
    listed = []
    nxt = None
    while True:
        resp = ct.list_trails(NextToken=nxt) if nxt else ct.list_trails()
        listed.extend(t["Name"] for t in resp["Trails"])
        nxt = resp.get("NextToken")
        if not nxt:
            break
    return described, listed


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """CreateTrail on a bucket without a CloudTrail delivery policy is rejected with
    InsufficientS3BucketPolicyException and creates nothing; the identical call on the same bucket
    succeeds once the policy is attached, and the deleted trail is then refused everywhere.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account = ctx.account

    bucket = ctx.unique_name("sim2real-behav-ct-nopol-").lower()
    _create_bucket_only(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]})

    name = ctx.unique_name("sim2real-behav-ct-trail-")

    # The rejection must be probed before the policy is attached; there is no way back after.
    code, status, message = _error_code(lambda: ct.create_trail(Name=name, S3BucketName=bucket))
    assert code == "InsufficientS3BucketPolicyException", (
        f"expected InsufficientS3BucketPolicyException creating a trail against a bucket with "
        f"no CloudTrail delivery policy, got {code!r}. The bucket {bucket!r} exists and is "
        f"owned by this account; the only thing wrong with the request is the missing policy."
    )
    assert status == 400, f"expected HTTP 400 for the unpolicied-bucket refusal, got {status!r}"
    # AWS's message names the bucket ('... detected for bucket: <bucket>').
    expected_message = f"Incorrect S3 bucket policy is detected for bucket: {bucket}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    described, listed = _paged_trail_names(ct)
    assert name not in described, (
        f"effect not absent: DescribeTrails lists the trail {name!r} after the rejection, so "
        f"something was created. Trails present: {described!r}"
    )
    assert name not in listed, (
        f"effect not absent: the paginated ListTrails lists the trail {name!r} after the "
        f"rejection. Trails present: {listed!r}"
    )
    get_code, _, message = _error_code(lambda: ct.get_trail(Name=name))
    assert get_code == "TrailNotFoundException", (
        f"GetTrail on the rejected name returned {get_code!r} instead of "
        f"TrailNotFoundException, so a partial trail survived the rejected create"
    )
    expected_message = f"Unknown trail: {name} for the user: {ctx.account}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    sel_code, _, message = _error_code(lambda: ct.get_event_selectors(TrailName=name))
    assert sel_code == "TrailNotFoundException", (
        f"GetEventSelectors on the rejected name returned {sel_code!r} instead of "
        f"TrailNotFoundException; a target that materialises default event selectors for a "
        f"trail it refused to create fails here"
    )
    expected_message = f"Unknown trail: arn:aws:cloudtrail:{ctx.region}:{ctx.account}:trail/{name} for the user: {ctx.account}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Bucket-policy propagation is eventually consistent, so _call retries
    # InsufficientS3BucketPolicyException within a bound.
    s3.put_bucket_policy(Bucket=bucket, Policy=_trail_delivery_policy(bucket, account))
    created = _call(lambda: ct.create_trail(Name=name, S3BucketName=bucket))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    assert created["Name"] == name, (
        f"positive control: the identical call must succeed once the bucket is policied, but the "
        f"created trail is named {created.get('Name')!r} rather than {name!r}"
    )
    assert created["S3BucketName"] == bucket, (
        f"the created trail points at {created.get('S3BucketName')!r} rather than the bucket "
        f"the request named ({bucket!r})"
    )
    fetched = _call(lambda: ct.get_trail(Name=name))["Trail"]
    assert fetched["S3BucketName"] == bucket, (
        f"GetTrail disagrees with CreateTrail about the delivery bucket: {fetched!r}"
    )
    assert fetched["TrailARN"] == created["TrailARN"], (
        f"GetTrail reports TrailARN {fetched.get('TrailARN')!r} but CreateTrail minted "
        f"{created.get('TrailARN')!r}"
    )
    described_after, _ = _paged_trail_names(ct)
    assert name in described_after, (
        f"the trail was created and GetTrail resolves it, but DescribeTrails does not list "
        f"{name!r}: {described_after!r}"
    )

    _call(lambda: ct.delete_trail(Name=name))
    gone_code, gone_status, gone_msg = _error_code(lambda: ct.get_trail(Name=name))
    assert gone_code == "TrailNotFoundException", f"GetTrail after delete: got {gone_code!r}"
    assert gone_status == 400, f"GetTrail after delete: expected HTTP 400, got {gone_status!r}"
    expected_message = f"Unknown trail: {name} for the user: {ctx.account}"
    assert gone_msg == expected_message, f"expected the message {expected_message!r}, got {gone_msg!r}"
    described_gone, listed_gone = _paged_trail_names(ct)
    assert name not in described_gone and name not in listed_gone, (
        f"deleted trail {name!r} is still listed: DescribeTrails={described_gone!r} ListTrails={listed_gone!r}"
    )
    upd_code, upd_status, upd_msg = _error_code(lambda: ct.update_trail(Name=name, S3BucketName=bucket))
    assert upd_code == "TrailNotFoundException", f"UpdateTrail after delete: got {upd_code!r}"
    assert upd_status == 400, f"UpdateTrail after delete: expected HTTP 400, got {upd_status!r}"
    expected_message = f"Unknown trail: {created['TrailARN']} for the user: {ctx.account}"
    assert upd_msg == expected_message, f"expected the message {expected_message!r}, got {upd_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
