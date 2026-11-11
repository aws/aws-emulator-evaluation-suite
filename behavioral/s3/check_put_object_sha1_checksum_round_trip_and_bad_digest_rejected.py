"""put-object-sha1-checksum-round-trip-and-bad-digest-rejected."""

from __future__ import annotations

import base64
import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-object-sha1-checksum-round-trip-and-bad-digest-rejected"
GROUP = "data-integrity"
SERVICES = ["s3"]

_BODY = b"sim2real-sha1-checksum-payload"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject ChecksumAlgorithm=SHA1 returns the true SHA1 on HeadObject/GetObject with
    ChecksumMode=ENABLED; a wrong x-amz-checksum-sha1 on the same bytes is BadDigest with its exact
    message and stores nothing."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "sha1-obj"
    expected = base64.b64encode(hashlib.sha1(_BODY).digest()).decode()

    put = s3.put_object(Bucket=bucket, Key=key, Body=_BODY, ChecksumAlgorithm="SHA1")
    assert put.get("ChecksumSHA1") == expected, (
        f"PutObject ChecksumSHA1 {put.get('ChecksumSHA1')!r} != recomputed SHA1 {expected!r}"
    )

    head = s3.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert head.get("ChecksumSHA1") == expected, (
        f"HeadObject(ChecksumMode=ENABLED) ChecksumSHA1 {head.get('ChecksumSHA1')!r} != {expected!r}"
    )

    got = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert got.get("ChecksumSHA1") == expected, (
        f"GetObject(ChecksumMode=ENABLED) ChecksumSHA1 {got.get('ChecksumSHA1')!r} != {expected!r}"
    )

    other = b"sim2real-different-bytes-for-the-mismatch"
    wrong = base64.b64encode(hashlib.sha1(other).digest()).decode()
    exc = _error(lambda: s3.put_object(
        Bucket=bucket, Key="sha1-bad-digest", Body=_BODY, ChecksumSHA1=wrong
    ))
    assert exc["Code"] == "BadDigest", f"expected BadDigest, got {exc!r}"
    assert exc["Message"] == "The SHA1 you specified did not match the calculated checksum.", (
        f"unexpected BadDigest message: {exc['Message']!r}"
    )

    listed = {o["Key"] for o in _list_all(s3, bucket)}
    assert listed == {key}, (
        f"only the accepted upload must land; bucket lists {listed!r}"
    )


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named, tagged bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: _empty_and_delete_bucket(s3, name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Delete every object then the bucket."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for o in page.get("Contents") or []:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
    s3.delete_bucket(Bucket=bucket)


def _list_all(s3, bucket: str) -> list[dict]:
    """Every ListObjectsV2 Contents entry, paginated."""
    out: list[dict] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        out.extend(page.get("Contents") or [])
    return out


def _error(fn) -> dict:
    """The AWS Error dict fn() raises; raises itself when the call SUCCEEDS (real AWS rejects it)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call succeeded; real AWS rejects it, so there is no error code")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
