"""bucket-holding-more-than-sixty-four-mib-reads-back-every-object."""

from __future__ import annotations

import hashlib
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-holding-more-than-sixty-four-mib-reads-back-every-object"
GROUP = "lifecycle"
SERVICES = ["s3"]

_OBJECTS = 5
_SIZE = 13 * 1024 * 1024  # 5 x 13 MiB = 65 MiB, each a single-part PutObject


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """One bucket stores 65 MiB as five 13 MiB single-part objects and serves all of them back.

    Every PutObject succeeds, the listing reports each size, GetObject returns every body exactly.
    """
    s3 = ctx.client("s3")
    bucket = _bucket(ctx)
    digests: dict[str, str] = {}
    for i in range(_OBJECTS):
        key = f"blob/{i}.bin"
        body = os.urandom(_SIZE)
        digests[key] = hashlib.md5(body).hexdigest()
        put = s3.put_object(Bucket=bucket, Key=key, Body=body)
        assert put["ETag"].strip('"') == digests[key], (
            f"PutObject {key} ETag {put['ETag']!r} must be the body's MD5 {digests[key]!r}"
        )

    listed = {o["Key"]: o["Size"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents") or []}
    assert listed == {k: _SIZE for k in digests}, (
        f"the bucket must list {_OBJECTS} {_SIZE}-byte objects; got {listed!r}"
    )

    for key, digest in digests.items():
        got = s3.get_object(Bucket=bucket, Key=key)
        data = got["Body"].read()
        assert got["ContentLength"] == _SIZE, (
            f"GetObject {key} ContentLength {got['ContentLength']} != {_SIZE}"
        )
        assert len(data) == _SIZE and hashlib.md5(data).hexdigest() == digest, (
            f"GetObject {key} returned {len(data)} bytes that differ from the {_SIZE} stored"
        )


def _bucket(ctx) -> str:
    """An unversioned bucket whose purge-and-delete net is registered before the create."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bigbkt-")
    ctx.on_cleanup(lambda: _drop_bucket(ctx, name))
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint
        # there, so it must be omitted rather than passed.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    return name


def _drop_bucket(ctx, bucket: str) -> None:
    """The cleanup: delete every object, then the bucket. A bucket never made is fine."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents") or []]
            if objs:
                out = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
                if out.get("Errors"):
                    raise AssertionError(f"cleanup could not delete {out['Errors'][:3]!r}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
