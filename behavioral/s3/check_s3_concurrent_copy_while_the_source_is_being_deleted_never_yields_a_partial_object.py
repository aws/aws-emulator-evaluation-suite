"""s3-concurrent-copy-while-the-source-is-being-deleted-never-yields-a-partial-object."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-concurrent-copy-while-the-source-is-being-deleted-never-yields-a-partial-object"
GROUP = 'concurrency'
SERVICES = ['s3']

_SIZE = 10 * 1024 * 1024      # 10 MiB — big enough that a non-atomic copy would be observable
_COPIES = 8
_SOURCE_KEY = "race-source.bin"


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": "true"}]})
    return name


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Eight concurrent CopyObjects racing a source delete each end whole (source bytes and ETag)
    or as NoSuchKey with no destination; a copy after the delete is NoSuchKey and creates nothing.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    source_bytes = os.urandom(_SIZE)
    source_etag = s3.put_object(Bucket=bucket, Key=_SOURCE_KEY, Body=source_bytes)["ETag"]
    assert s3.head_object(Bucket=bucket, Key=_SOURCE_KEY)["ContentLength"] == _SIZE, (
        f"the source object is not {_SIZE} bytes"
    )

    def _copy(index):
        dest = f"race-dest-{index}.bin"
        try:
            resp = s3.copy_object(
                Bucket=bucket, Key=dest,
                CopySource={"Bucket": bucket, "Key": _SOURCE_KEY},
            )
            return dest, resp["CopyObjectResult"]["ETag"], None
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return dest, None, (err.get("Code"), err.get("Message"))

    def _delete_source():
        s3.delete_object(Bucket=bucket, Key=_SOURCE_KEY)
        return None

    # How many copies win is scheduler-dependent, so only the per-destination outcome is asserted.
    with ThreadPoolExecutor(max_workers=_COPIES + 1) as pool:
        futures = [pool.submit(_copy, i) for i in range(_COPIES)]
        futures.append(pool.submit(_delete_source))
        outcomes = [f.result() for f in futures[:_COPIES]]
        futures[_COPIES].result()  # re-raise anything the delete thread hit

    succeeded, failed = [], []
    for dest, etag, code in outcomes:
        (succeeded if code is None else failed).append((dest, etag, code))
    assert len(succeeded) + len(failed) == _COPIES, (
        f"accounted for {len(succeeded) + len(failed)} outcomes, launched {_COPIES}"
    )

    for dest, etag, _ in succeeded:
        assert etag == source_etag, (
            f"{dest} was copied with ETag {etag!r} but the source's is {source_etag!r} — a "
            "server-side copy of unchanged bytes must preserve the ETag, so this destination "
            "holds different content"
        )
        got = s3.get_object(Bucket=bucket, Key=dest)
        body = got["Body"].read()
        assert body == source_bytes, (
            f"{dest} holds {len(body)} bytes, the source held {_SIZE} — a copy that raced the "
            "source's deletion produced a PARTIAL object, which CopyObject's atomicity forbids"
        )
        head = s3.head_object(Bucket=bucket, Key=dest)
        assert head["ContentLength"] == _SIZE, (
            f"{dest} reports ContentLength {head['ContentLength']!r}, want {_SIZE}"
        )
        assert head["ETag"] == source_etag, (
            f"{dest} reports ETag {head['ETag']!r} on a HEAD, want {source_etag!r}"
        )

    for dest, _, code in failed:
        assert code == ("NoSuchKey", "The specified key does not exist."), (
            f"{dest}'s copy failed with {code!r}; the only legal failure when the source is "
            "concurrently deleted is NoSuchKey"
        )
        absent = _client_error(lambda d=dest: s3.head_object(Bucket=bucket, Key=d))
        assert absent is not None, (
            f"{dest}'s copy reported {code!r} but the destination object EXISTS — a failed copy "
            "must not leave a partial or empty object at the destination"
        )
        assert absent.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
            f"HeadObject on the failed destination {dest} returned "
            f"{absent.response['ResponseMetadata']['HTTPStatusCode']!r}, expected 404"
        )

    listed = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        listed |= {o["Key"] for o in page.get("Contents", [])}
    assert listed == {dest for dest, _, _ in succeeded}, (
        f"the bucket lists {sorted(listed)!r}; the successful copies were "
        f"{sorted(dest for dest, _, _ in succeeded)!r} and the source was deleted — anything "
        "else is a destination that exists for a copy that failed, or a source that survived"
    )

    # The delete often lands last and every copy succeeds; this deterministic copy from the
    # now-deleted source exercises the failure branch regardless.
    late_dest = "race-dest-after.bin"
    late = _client_error(lambda: s3.copy_object(
        Bucket=bucket, Key=late_dest, CopySource={"Bucket": bucket, "Key": _SOURCE_KEY},
    ))
    assert late is not None, (
        f"CopyObject succeeded with {_SOURCE_KEY!r} as its source after that key was deleted — "
        "the copy is reading stale state"
    )
    assert late.response["Error"]["Code"] == "NoSuchKey", (
        f"expected NoSuchKey copying from a deleted source, got "
        f"{late.response['Error']['Code']!r}"
    )
    assert late.response["Error"].get("Message") == "The specified key does not exist.", (
        f"unexpected NoSuchKey message copying from a deleted source: "
        f"{late.response['Error'].get('Message')!r}"
    )
    assert late.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404, got {late.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    late_absent = _client_error(lambda: s3.head_object(Bucket=bucket, Key=late_dest))
    assert late_absent is not None, (
        f"the refused copy created {late_dest!r} anyway"
    )
    assert late_absent.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"HeadObject on {late_dest!r} returned "
        f"{late_absent.response['ResponseMetadata']['HTTPStatusCode']!r}, expected 404"
    )
    still_listed = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        still_listed |= {o["Key"] for o in page.get("Contents", [])}
    assert still_listed == listed, (
        f"the refused copy changed the bucket: {sorted(still_listed)!r} vs {sorted(listed)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
