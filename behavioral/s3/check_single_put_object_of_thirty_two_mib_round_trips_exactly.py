"""single-put-object-of-thirty-two-mib-round-trips-exactly."""

from __future__ import annotations

import hashlib
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "single-put-object-of-thirty-two-mib-round-trips-exactly"
GROUP = "lifecycle"
SERVICES = ["s3"]

_SIZE = 32 * 1024 * 1024  # 33554432 bytes, well under the 5 GiB single-PUT maximum


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single 32 MiB PutObject succeeds; HeadObject and GetObject report the same size
    and ETag, and GetObject returns the exact bytes written.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "lifecycle/large-object.bin"
    body = os.urandom(_SIZE)
    digest = hashlib.md5(body).hexdigest()

    put = s3.put_object(Bucket=bucket, Key=key, Body=body)
    assert put["ETag"] == f'"{digest}"', (
        f"PutObject ETag {put['ETag']!r} must be the quoted MD5 {digest!r} of the body"
    )

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] == _SIZE, (
        f"HeadObject ContentLength {head['ContentLength']} != {_SIZE}"
    )
    assert head["ETag"] == put["ETag"], (
        f"HeadObject ETag {head['ETag']!r} != the ETag PutObject returned {put['ETag']!r}"
    )

    got = s3.get_object(Bucket=bucket, Key=key)
    assert got["ContentLength"] == _SIZE, (
        f"GetObject ContentLength {got['ContentLength']} != {_SIZE}"
    )
    data = got["Body"].read()
    assert len(data) == _SIZE, f"GetObject returned {len(data)} bytes, expected {_SIZE}"
    assert data == body, "GetObject returned bytes that differ from the body that was put"


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-bigobj-")
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint
        # there, so it must be omitted rather than passed.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _delete_bucket(client, bucket: str) -> None:
    """Empty the bucket then delete it. Tolerates only NoSuchBucket; any other error raises."""
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents") or []]
            if objs:
                out = client.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
                if out.get("Errors"):
                    raise AssertionError(f"cleanup could not delete {out['Errors'][:3]!r}")
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
