"""virtual-hosted-and-path-style-clients-agree-on-an-objects-full-lifecycle."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "virtual-hosted-and-path-style-clients-agree-on-an-objects-full-lifecycle"
GROUP = "addressing"
SERVICES = ["s3"]

KEY = "cross-addr/lifecycle.bin"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    s3.delete_bucket(Bucket=bucket)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A virtual-hosted client's PutObject, HeadObject, GetObject, ListObjectsV2 and HeadBucket on
    one bucket read back identically through a path-style client, and after DeleteObject both
    addressing forms agree the key and its listing entry are gone.
    """
    plain = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-bkt-")
    create = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    plain.create_bucket(**create)
    ctx.on_cleanup(_teardown(lambda: _empty_and_delete_bucket(plain, bucket), "NoSuchBucket"))

    vhost = ctx.client("s3", config=Config(s3={"addressing_style": "virtual"}, retries={"max_attempts": 1}))
    pstyle = ctx.client("s3", config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))

    body = b"cross-addressing-style payload"
    put = vhost.put_object(Bucket=bucket, Key=KEY, Body=body, ContentType="application/octet-stream")
    etag = put["ETag"]

    vhead = vhost.head_object(Bucket=bucket, Key=KEY)
    assert vhead["ContentLength"] == len(body), (
        f"virtual-hosted HeadObject ContentLength {vhead['ContentLength']}, wrote {len(body)}"
    )
    assert vhead["ETag"] == etag, f"virtual-hosted HeadObject ETag {vhead['ETag']!r}, expected {etag!r}"
    vgot = vhost.get_object(Bucket=bucket, Key=KEY)
    assert vgot["Body"].read() == body, "virtual-hosted GetObject did not return the written bytes"
    assert vgot["ETag"] == etag, f"virtual-hosted GetObject ETag {vgot['ETag']!r}, expected {etag!r}"
    vlisted = vhost.list_objects_v2(Bucket=bucket, Prefix="cross-addr/").get("Contents", [])
    assert [o["Key"] for o in vlisted] == [KEY], (
        f"virtual-hosted ListObjectsV2 listed {[o['Key'] for o in vlisted]!r}"
    )
    assert vlisted[0]["ETag"] == etag, f"virtual-hosted listing ETag {vlisted[0]['ETag']!r}, expected {etag!r}"
    vheadbucket = vhost.head_bucket(Bucket=bucket)
    assert vheadbucket["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"virtual-hosted HeadBucket answered {vheadbucket['ResponseMetadata']}"
    )

    phead = pstyle.head_object(Bucket=bucket, Key=KEY)
    assert phead["ContentLength"] == vhead["ContentLength"], (
        f"path-style HeadObject ContentLength {phead['ContentLength']}, virtual-hosted saw {vhead['ContentLength']}"
    )
    assert phead["ETag"] == etag, f"path-style HeadObject ETag {phead['ETag']!r}, expected {etag!r}"
    pgot = pstyle.get_object(Bucket=bucket, Key=KEY)
    assert pgot["Body"].read() == body, "path-style GetObject did not return the written bytes"
    assert pgot["ETag"] == etag, f"path-style GetObject ETag {pgot['ETag']!r}, expected {etag!r}"
    plisted = pstyle.list_objects_v2(Bucket=bucket, Prefix="cross-addr/").get("Contents", [])
    assert [o["Key"] for o in plisted] == [KEY], (
        f"path-style ListObjectsV2 listed {[o['Key'] for o in plisted]!r}"
    )
    assert plisted[0]["ETag"] == etag, f"path-style listing ETag {plisted[0]['ETag']!r}, expected {etag!r}"
    pheadbucket = pstyle.head_bucket(Bucket=bucket)
    assert pheadbucket["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"path-style HeadBucket answered {pheadbucket['ResponseMetadata']}"
    )

    vhost.delete_object(Bucket=bucket, Key=KEY)

    no_key = ("NoSuchKey", "The specified key does not exist.")
    for client, label in ((vhost, "virtual-hosted"), (pstyle, "path-style")):
        code, message = _error(lambda c=client: c.get_object(Bucket=bucket, Key=KEY))
        assert (code, message) == no_key, (
            f"{label} GetObject after delete: expected {no_key}, got {(code, message)!r}"
        )
        after = client.list_objects_v2(Bucket=bucket, Prefix="cross-addr/").get("Contents", [])
        assert after == [], f"{label} ListObjectsV2 still lists the deleted key: {[o['Key'] for o in after]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
