"""create-trail-nonexistent-bucket-fails."""

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
    """Empty and delete the bucket, retrying because CloudTrail may still be writing, and RAISE
    on a genuine deadline miss so a leaked billable bucket is visible rather than silent."""
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


def _error(fn):
    """Call fn() and return the (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS raises, so a target that accepts a call real AWS refuses fails loudly
    rather than reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _paged_trail_names(ct):
    """Every trail name, from BOTH listing operations, paginated, so a membership decision is
    never made from one page."""
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


CHECK = "create-trail-nonexistent-bucket-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrail naming a nonexistent bucket fails with S3BucketDoesNotExistException and its exact message
    and creates nothing (absent from DescribeTrails, ListTrails and GetTrail), and the identical call
    succeeds once that bucket exists with the CloudTrail delivery policy.
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-ct-trail-")
    missing_bucket = ctx.unique_name("sim2real-behav-ct-missing-bkt-").lower()

    # (a) the exact error code, from a helper that raises rather than returning a sentinel.
    code, msg = _error(lambda: ct.create_trail(Name=name, S3BucketName=missing_bucket))
    assert code == "S3BucketDoesNotExistException", (
        f"expected S3BucketDoesNotExistException creating a trail against a bucket that does "
        f"not exist ({missing_bucket!r}), got {code!r}"
    )
    assert msg == f"S3 bucket {missing_bucket} does not exist!", msg

    # (b) the effect is ABSENT -- in both listings and in the single-resource read.
    described, listed = _paged_trail_names(ct)
    assert name not in described, (
        f"effect not absent: DescribeTrails lists the trail {name!r} after the rejection, so "
        f"something was created. Trails present: {described!r}"
    )
    assert name not in listed, (
        f"effect not absent: the paginated ListTrails lists the trail {name!r} after the "
        f"rejection. Trails present: {listed!r}"
    )
    get_code, get_msg = _error(lambda: ct.get_trail(Name=name))
    assert get_code == "TrailNotFoundException", (
        f"GetTrail on the rejected name returned {get_code!r} instead of TrailNotFoundException, "
        f"so a partial trail survived the rejected create"
    )
    assert get_msg == f"Unknown trail: {name} for the user: {account}", get_msg

    # (c) the positive control: create the SAME bucket the rejected call named, policy it for
    # CloudTrail delivery, and retry the IDENTICAL call. A different bucket would reintroduce a
    # second variable and no longer isolate "the bucket did not exist" as the one broken thing.
    _create_bucket_only(s3, missing_bucket, ctx.region)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, missing_bucket))
    s3.put_bucket_tagging(Bucket=missing_bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]})
    s3.put_bucket_policy(Bucket=missing_bucket, Policy=_trail_delivery_policy(missing_bucket, account))

    created = _call(lambda: ct.create_trail(Name=name, S3BucketName=missing_bucket))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    assert created["Name"] == name, (
        f"positive control: the identical call must succeed once the bucket exists and is "
        f"policied, but the created trail is named {created.get('Name')!r} rather than {name!r}"
    )
    assert created["S3BucketName"] == missing_bucket, (
        f"the created trail points at {created.get('S3BucketName')!r} rather than the bucket "
        f"the request named ({missing_bucket!r})"
    )
    fetched = _call(lambda: ct.get_trail(Name=name))["Trail"]
    assert fetched["S3BucketName"] == missing_bucket, (
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
