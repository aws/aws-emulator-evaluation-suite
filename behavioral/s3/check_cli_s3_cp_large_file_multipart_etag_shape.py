"""cli-s3-cp-large-file-multipart-etag-shape."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from fidelity_tests_runner import require_tools

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cli-s3-cp-large-file-multipart-etag-shape"
GROUP = "cli-multipart"
SERVICES = ["s3"]

_SIZE = 20 * 1024 * 1024  # over the CLI's 8 MiB multipart threshold, so this always splits
_PART = 8 * 1024 * 1024  # the CLI's default multipart_chunksize; its config file is empty here


def _bucket_kwargs(ctx, name: str) -> dict:
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            targets = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _run(argv, env, timeout_s=180):
    r = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout_s)
    assert r.returncode == 0, f"{' '.join(argv)} failed (rc={r.returncode}): {r.stderr[-600:]!r}"
    return r


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws s3 cp` of a 20 MiB file uploads as three 8 MiB-chunked parts, the stored ETag is the
    MD5 of the concatenated part MD5s suffixed '-3', and a download round-trips the exact bytes.
    """
    require_tools("aws")
    ctx.verify_account_safety()
    s3 = ctx.client("s3")
    env = ctx.subprocess_env()
    bucket = ctx.unique_name("sim2real-behav-cpmpu-")
    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    work = Path(tempfile.mkdtemp(prefix="sim2real-cpmpu-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work))
    payload = os.urandom(_SIZE)
    local = work / "large.bin"
    local.write_bytes(payload)

    key = "large.bin"
    _run(["aws", "s3", "cp", str(local), f"s3://{bucket}/{key}"], env)

    attrs = s3.get_object_attributes(Bucket=bucket, Key=key, ObjectAttributes=["ObjectParts"])
    total_parts = attrs["ObjectParts"]["TotalPartsCount"]
    chunks = [payload[i:i + _PART] for i in range(0, _SIZE, _PART)]
    assert total_parts == len(chunks) == 3, (
        f"expected `aws s3 cp` of {_SIZE} bytes in {_PART}-byte parts to upload 3 parts, "
        f"got TotalPartsCount {total_parts}"
    )

    head = s3.head_object(Bucket=bucket, Key=key)
    etag = head["ETag"].strip('"')
    want = hashlib.md5(b"".join(hashlib.md5(c).digest() for c in chunks)).hexdigest() + "-3"
    assert etag == want, f"multipart ETag read as {etag!r}, expected the MD5 of the part MD5s {want!r}"

    download = work / "roundtrip.bin"
    _run(["aws", "s3", "cp", f"s3://{bucket}/{key}", str(download)], env)
    assert download.read_bytes() == payload, "the multipart upload did not round-trip byte-exact"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
