"""op-contract-create-trail."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-trail"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrail returns the trail's identity fields; recreating an existing Name is rejected."""
    ct = ctx.client("cloudtrail")
    bucket, account_id = _create_trail_bucket(ctx)
    name = ctx.unique_name("sim2real-ct-trail-")

    resp = _create_trail_retrying(
        ct,
        Name=name,
        S3BucketName=bucket,
        IncludeGlobalServiceEvents=True,
        IsMultiRegionTrail=False,
        EnableLogFileValidation=True,
    )
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    ct.add_tags(ResourceId=resp["TrailARN"], TagsList=[
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}])

    assert resp["Name"] == name, f"expected Name={name!r}, got {resp.get('Name')!r}"
    assert resp["S3BucketName"] == bucket, (
        f"expected S3BucketName={bucket!r}, got {resp.get('S3BucketName')!r}"
    )
    assert resp["IsMultiRegionTrail"] is False, (
        f"expected IsMultiRegionTrail=False, got {resp.get('IsMultiRegionTrail')!r}"
    )
    assert resp["LogFileValidationEnabled"] is True, (
        f"expected LogFileValidationEnabled=True, got {resp.get('LogFileValidationEnabled')!r}"
    )
    expected_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:trail/{name}"
    assert resp["TrailARN"] == expected_arn, (
        f"expected TrailARN={expected_arn!r}, got {resp.get('TrailARN')!r}"
    )

    # Error boundary: creating a trail with a Name that already exists is rejected, and the
    # original trail is left untouched (still exactly one trail with this name).
    code, message = _error(lambda: ct.create_trail(Name=name, S3BucketName=bucket))
    assert code == "TrailAlreadyExistsException", (
        f"expected TrailAlreadyExistsException recreating an existing trail Name, got {code!r}"
    )
    assert message == f"Trail {name} already exists for customer: {account_id}", message

    described = ct.describe_trails(trailNameList=[name])["trailList"]
    assert len(described) == 1, (
        f"expected exactly 1 trail named {name!r} after the rejected recreate, got {len(described)}"
    )
    assert described[0]["S3BucketName"] == bucket, (
        f"expected the original trail's S3BucketName to remain {bucket!r} after the rejected "
        f"recreate, got {described[0].get('S3BucketName')!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


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
    # us-east-1 is the one region S3's CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(_bucket_policy(bucket, account_id)))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]})

    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    return bucket, account_id


def _purge_bucket_once(s3, bucket):
    from botocore.exceptions import ClientError

    for pname, list_key, id_key in (
        ("list_objects_v2", "Contents", None),
        ("list_object_versions", "Versions", "VersionId"),
        ("list_object_versions", "DeleteMarkers", "VersionId"),
    ):
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
    """Empty and delete the log bucket, retrying because CloudTrail may still be writing logs,
    which makes DeleteBucket fail with BucketNotEmpty; raises when every attempt fails."""
    from botocore.exceptions import ClientError

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
        f"could not delete bucket {bucket!r} after {attempts} attempts; a billable S3 bucket "
        f"has been leaked. Last error: {last}"
    )


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
