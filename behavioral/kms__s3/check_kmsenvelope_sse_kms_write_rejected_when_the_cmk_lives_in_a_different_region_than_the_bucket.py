"""kmsenvelope-sse-kms-write-rejected-when-the-cmk-lives-in-a-different-region-than-the-bucket."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kmsenvelope-sse-kms-write-rejected-when-the-cmk-lives-in-a-different-region-than-the-bucket"
GROUP = "encryption-rejection"
SERVICES = ["kms", "s3"]

#: describe_regions reports these two opt-in states for regions this account may use; anything
#: else ("not-opted-in") is a region the account cannot reach and must not be chosen.
_ENABLED_OPT_IN = ("opt-in-not-required", "opted-in")


def _client_error(fn, accepted):
    """Call fn(); return the ClientError it raised. A normal return fails with ``accepted``."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(accepted)


def _delete_bucket(s3, bucket: str) -> None:
    """Delete every object this check's own bucket holds, then the bucket."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, region: str) -> str:
    """Create a uniquely named, sim2real-tagged bucket IN region and register its teardown."""
    bucket = ctx.unique_name("sim2real-behav-kmsenv-xregion-").lower()
    params = {"Bucket": bucket}
    if region != "us-east-1":
        # us-east-1 is the one region whose CreateBucket rejects an explicit LocationConstraint.
        params["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "kmsenvelope-cross-region"}]},
    )
    return bucket


def _retire_key(kms, key_id: str) -> None:
    """Schedule the CMK for deletion with the 7-day minimum window AWS enforces.

    KMS has no synchronous key delete, so the key stays in PendingDeletion afterwards. The client
    is passed in because a key can only be retired through its own region.
    """
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return
            if code != "ThrottlingException" or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _second_region(ec2, home: str) -> str:
    """Pick a region other than `home` from what this account reports as enabled.

    A not-opted-in region answers every call with an authorization failure that would read like
    the rejection under test, so only enabled regions are candidates.
    """
    regions = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": list(_ENABLED_OPT_IN)}]
    )["Regions"]
    enabled = {r["RegionName"]: r["OptInStatus"] for r in regions}
    candidates = sorted(name for name in enabled if name != home)
    assert candidates, (
        f"this account reports no enabled region other than {home!r} ({sorted(enabled)!r}), so a "
        "cross-region claim cannot be established here"
    )
    chosen = candidates[0]
    assert enabled[chosen] in _ENABLED_OPT_IN, (
        f"chose {chosen!r} but its opt-in status is {enabled[chosen]!r}, which is not an enabled "
        f"state ({_ENABLED_OPT_IN!r})"
    )
    return chosen


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An SSE-KMS PutObject naming a CMK from another region is refused KMS.NotFoundException/400
    and stores nothing (HeadObject 404), while the identical write with a CMK in the bucket's own
    region succeeds and reads back byte for byte.
    """
    ec2 = ctx.client("ec2")
    home_kms = ctx.client("kms")
    other_region = _second_region(ec2, ctx.region)
    assert other_region != ctx.region, (
        f"the derived second region is {other_region!r}, which is the region under test"
    )
    remote_kms = ctx.client("kms", region=other_region)
    remote_s3 = ctx.client("s3", region=other_region)

    home_key = home_kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsenv-xregion-home-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kmsenvelope-cross-region"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: _retire_key(home_kms, home_key["KeyId"]))
    assert f":{ctx.region}:" in home_key["Arn"], (
        f"the home CMK's ARN {home_key['Arn']!r} does not name {ctx.region!r}"
    )

    bucket = _new_bucket(ctx, remote_s3, other_region)
    # GetBucketLocation answers a null LocationConstraint for us-east-1, which is the documented
    # spelling of that region rather than an absent answer.
    located = remote_s3.get_bucket_location(Bucket=bucket).get("LocationConstraint") or "us-east-1"
    assert located == other_region, (
        f"the bucket was created in {located!r}, not the derived second region {other_region!r} — "
        "the rest of this check would not be cross-region at all"
    )

    obj = "envelope/cross-region.bin"
    payload = b"kmsenvelope-cross-region-payload-" + os.urandom(40)

    refusal = _client_error(
        lambda: remote_s3.put_object(
            Bucket=bucket, Key=obj, Body=payload,
            ServerSideEncryption="aws:kms", SSEKMSKeyId=home_key["Arn"], BucketKeyEnabled=False,
        ),
        accepted=(
            f"PutObject accepted SSEKMSKeyId {home_key['Arn']!r} — a key in {ctx.region!r} — for "
            f"a bucket in {other_region!r}; S3 must resolve the ARN against its own region's KMS"
        ),
    )
    code = refusal.response.get("Error", {}).get("Code")
    assert code == "KMS.NotFoundException", (
        f"expected KMS.NotFoundException for a foreign-region key ARN, got {code!r} — S3 surfaces "
        "this FROM KMS, so anything else means the ARN was never resolved"
    )
    message = refusal.response.get("Error", {}).get("Message")
    # S3 names the region of the key ARN it could not resolve.
    key_region = home_key["Arn"].split(":")[3]
    assert message == f"Invalid arn {key_region}", (
        f"KMS.NotFoundException message was {message!r}, expected 'Invalid arn {key_region}'"
    )
    assert refusal.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"expected HTTP 400, got {refusal.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    missing = _client_error(
        lambda: remote_s3.head_object(Bucket=bucket, Key=obj),
        accepted=(
            f"HeadObject found {obj!r} after the write was refused — a rejected SSE-KMS write "
            "must store nothing"
        ),
    )
    assert missing.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for the object the refused write did not create, got "
        f"{missing.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # Positive control: a CMK in the bucket's own region takes the identical write.
    remote_key = remote_kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsenv-xregion-local-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kmsenvelope-cross-region"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: _retire_key(remote_kms, remote_key["KeyId"]))
    assert f":{other_region}:" in remote_key["Arn"], (
        f"the second CMK's ARN {remote_key['Arn']!r} does not name {other_region!r}"
    )

    put = remote_s3.put_object(
        Bucket=bucket, Key=obj, Body=payload,
        ServerSideEncryption="aws:kms", SSEKMSKeyId=remote_key["Arn"], BucketKeyEnabled=False,
    )
    assert put["SSEKMSKeyId"] == remote_key["Arn"], (
        f"PutObject reported SSEKMSKeyId {put.get('SSEKMSKeyId')!r}, want {remote_key['Arn']!r}"
    )
    fetched = remote_s3.get_object(Bucket=bucket, Key=obj)
    body = fetched["Body"].read()
    assert body == payload, (
        f"the same-region SSE-KMS write round-tripped to {len(body)} bytes, want {len(payload)} — "
        "the rejection above must be about the key's region, not about the request"
    )
    assert fetched["SSEKMSKeyId"] == remote_key["Arn"], (
        f"GetObject reported SSEKMSKeyId {fetched.get('SSEKMSKeyId')!r}, want "
        f"{remote_key['Arn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
