"""sse-kms-nonexistent-alias-rejected-and-no-object-created."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sse-kms-nonexistent-alias-rejected-and-no-object-created"
GROUP = "server-side-encryption"
SERVICES = ["kms", "s3"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SSE-KMS PutObject naming a nonexistent KMS alias is refused KMS.NotFoundException and
    stores nothing, while the identical write under a real alias succeeds and reads back.
    """
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    ghost_alias = ctx.unique_name("sim2real-behav-ssekms-ghost-")
    code, message = _rejected(
        lambda: s3.put_object(
            Bucket=bucket,
            Key="denied/ghost.bin",
            Body=b"should-never-land",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=f"alias/{ghost_alias}",
        )
    )
    assert code == "KMS.NotFoundException", (
        f"PutObject under a nonexistent alias must fail naming the alias as not found with "
        f"KMS.NotFoundException, got {code!r}"
    )
    assert message == (
        f"Alias arn:aws:kms:{ctx.region}:{ctx.account}:alias/{ghost_alias} is not found."), (
        f"the nonexistent-alias refusal message is {message!r}"
    )

    head_code = _rejected_code(lambda: s3.head_object(Bucket=bucket, Key="denied/ghost.bin"))
    assert head_code == "404", (
        f"no object may exist at 'denied/ghost.bin' after the refused write; HeadObject gave "
        f"{head_code!r}"
    )
    listed = [
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="denied/")
        for o in page.get("Contents", [])
    ]
    assert listed == [], f"the refused write must leave nothing under 'denied/', found {listed!r}"

    # Positive control: the identical write under a real alias succeeds.
    key_arn = _new_cmk(ctx, kms)
    real_alias = ctx.unique_name("sim2real-behav-ssekms-real-")
    kms.create_alias(AliasName=f"alias/{real_alias}", TargetKeyId=key_arn)
    ctx.on_cleanup(lambda: kms.delete_alias(AliasName=f"alias/{real_alias}"))

    # A just-created alias can briefly 404 before it propagates; wait for KMS's own DescribeKey
    # to see it before trusting a PutObject failure under it as anything but propagation lag.
    _poll_until(
        lambda: _describe_key_or_none(kms, f"alias/{real_alias}"),
        lambda arn: arn is not None,
        timeout_s=30,
        description=f"alias/{real_alias} to resolve via DescribeKey",
    )

    put = s3.put_object(
        Bucket=bucket,
        Key="ok/real.bin",
        Body=b"should-land",
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=f"alias/{real_alias}",
    )
    assert put.get("SSEKMSKeyId") == key_arn, (
        f"positive control: PutObject under a REAL alias must resolve to the real key ARN, got "
        f"{put.get('SSEKMSKeyId')!r}, expected {key_arn!r}"
    )
    got = s3.get_object(Bucket=bucket, Key="ok/real.bin")["Body"].read()
    assert got == b"should-land", (
        f"positive control: the write under the real alias must read back exactly, got {got!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_key_or_none(kms, key_id: str) -> str | None:
    try:
        return kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return None
        raise


def _new_cmk(ctx, kms) -> str:
    """A fresh symmetric CMK; schedules its 7-day deletion (the AWS minimum window)."""
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-ssekms-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _new_bucket(ctx, s3) -> str:
    """A private bucket in ctx.region, emptied (objects + versions) then deleted at teardown."""
    name = ctx.unique_name("sim2real-behav-ssekms-")
    create_kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _rejected(fn):
    """(code, message) of a call real AWS refuses; an unexpected SUCCESS raises with the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _rejected_code(fn):
    """The AWS error code of a call real AWS refuses; an unexpected SUCCESS raises with the
    result (never returns a falsy sentinel that could be confused with a code)."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
