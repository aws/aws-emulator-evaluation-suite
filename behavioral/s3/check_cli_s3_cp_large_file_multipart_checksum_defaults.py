"""cli-s3-cp-large-file-multipart-checksum-defaults."""
from __future__ import annotations

import base64
import os
import subprocess
import tempfile
import zlib
from pathlib import Path

from fidelity_tests_runner import require_tools

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cli-s3-cp-large-file-multipart-checksum-defaults"
GROUP = "cli-multipart-checksum"
SERVICES = ["s3"]

_SIZE = 12 * 1024 * 1024  # the CLI's default 8 MiB part size splits this into 2 parts


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws s3 cp` of a large file uploads in parts; the stored checksum (requested SHA256 or the
    CLI's default) is correct over the actual part split, and both uploads download byte-exact.
    """
    require_tools("aws")
    ctx.verify_account_safety()
    s3 = ctx.client("s3")
    env = ctx.subprocess_env()
    bucket = ctx.unique_name("sim2real-behav-clichk-")
    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    work = Path(tempfile.mkdtemp(prefix="sim2real-clichk-"))
    payload = os.urandom(_SIZE)
    local = work / "large.bin"
    local.write_bytes(payload)

    # --- Leg 1: explicit --checksum-algorithm SHA256 (always COMPOSITE for SHA256).
    sha_key = "large-sha256.bin"
    _run(["aws", "s3", "cp", str(local), f"s3://{bucket}/{sha_key}",
          "--checksum-algorithm", "SHA256"], env)

    sha_head = s3.head_object(Bucket=bucket, Key=sha_key, ChecksumMode="ENABLED")
    assert sha_head.get("ChecksumType") == "COMPOSITE", (
        f"a SHA256 upload must be COMPOSITE, got ChecksumType={sha_head.get('ChecksumType')!r}"
    )
    sha_sizes = _part_sizes(s3, bucket, sha_key)
    assert len(sha_sizes) > 1, f"expected a multipart upload of {_SIZE} bytes, got parts {sha_sizes!r}"
    assert sum(sha_sizes) == _SIZE, f"part sizes {sha_sizes!r} do not sum to {_SIZE}"
    expected_sha_composite = _sha256_composite_by_sizes(payload, sha_sizes)
    assert sha_head["ChecksumSHA256"] == f"{expected_sha_composite}-{len(sha_sizes)}", (
        f"HeadObject ChecksumSHA256 {sha_head['ChecksumSHA256']!r} != the digest computed "
        f"locally from the real part sizes {sha_sizes!r}: {expected_sha_composite!r}-{len(sha_sizes)}"
    )

    sha_download = work / "sha256-roundtrip.bin"
    _run(["aws", "s3", "cp", f"s3://{bucket}/{sha_key}", str(sha_download)], env)
    assert sha_download.read_bytes() == payload, "the SHA256-checksummed upload did not round-trip byte-exact"

    # No --checksum-algorithm: the default algorithm varies by CLI version, so accept any but
    # require the stored value to be correct for it.
    default_key = "large-default.bin"
    _run(["aws", "s3", "cp", str(local), f"s3://{bucket}/{default_key}"], env)

    default_head = s3.head_object(Bucket=bucket, Key=default_key, ChecksumMode="ENABLED")
    default_parts_count = _total_parts(s3, bucket, default_key)
    assert default_parts_count > 1, (
        f"expected the plain cp of {_SIZE} bytes to also be multipart, got "
        f"{default_parts_count} part(s)"
    )
    _assert_default_checksum_matches(default_head, payload, s3, bucket, default_key)

    default_download = work / "default-roundtrip.bin"
    _run(["aws", "s3", "cp", f"s3://{bucket}/{default_key}", str(default_download)], env)
    assert default_download.read_bytes() == payload, "the default-checksum upload did not round-trip byte-exact"


def _bucket_kwargs(ctx, name: str) -> dict:
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
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
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _run(argv, env, timeout_s=180):
    r = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout_s)
    assert r.returncode == 0, f"{' '.join(argv)} failed (rc={r.returncode}): {r.stderr[-600:]!r}"
    return r


def _part_sizes(s3, bucket, key) -> list[int]:
    """Per-part sizes. Only reported when ObjectParts actually lists parts — true for a
    COMPOSITE checksum (built from per-part digests); a FULL_OBJECT checksum has no per-part
    state to report at all, only a TotalPartsCount (see _total_parts)."""
    attrs = s3.get_object_attributes(Bucket=bucket, Key=key, ObjectAttributes=["ObjectParts"])
    return [p["Size"] for p in attrs["ObjectParts"]["Parts"]]


def _total_parts(s3, bucket, key) -> int:
    attrs = s3.get_object_attributes(Bucket=bucket, Key=key, ObjectAttributes=["ObjectParts"])
    return attrs["ObjectParts"]["TotalPartsCount"]


def _sha256_composite_by_sizes(payload: bytes, sizes: list[int]) -> str:
    import hashlib
    offset, digests = 0, b""
    for size in sizes:
        digests += hashlib.sha256(payload[offset:offset + size]).digest()
        offset += size
    return base64.b64encode(hashlib.sha256(digests).digest()).decode()


def _crc32_b64(data: bytes) -> str:
    return base64.b64encode(zlib.crc32(data).to_bytes(4, "big")).decode()


def _crc32_composite_by_sizes(payload: bytes, sizes: list[int]) -> str:
    offset, digests = 0, b""
    for size in sizes:
        digests += zlib.crc32(payload[offset:offset + size]).to_bytes(4, "big")
        offset += size
    return _crc32_b64(digests)


# CRC-64/NVME: poly 0xAD93D23594C93659 reflected, init/xorout all-ones, refin/refout. Table
# constant is bit-reverse(poly).
_CRC64_TABLE = []
for _byte in range(256):
    _crc = _byte
    for _ in range(8):
        _crc = (_crc >> 1) ^ (0x9A6C9329AC4BC9B5 if _crc & 1 else 0)
    _CRC64_TABLE.append(_crc)


def _crc64nvme_b64(data: bytes) -> str:
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc = _CRC64_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return base64.b64encode((crc ^ 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")).decode()


def _assert_default_checksum_matches(head: dict, payload: bytes, s3, bucket: str, key: str) -> None:
    """Whatever (algorithm, ChecksumType) the installed CLI defaulted to, the stored value must
    be the arithmetically correct one for that pair over the real bytes (FULL_OBJECT: a hash of
    the whole payload) or the real part split (COMPOSITE: fetched fresh, since only COMPOSITE
    reports per-part sizes at all)."""
    ctype = head.get("ChecksumType")
    if head.get("ChecksumCRC32") is not None:
        if ctype == "COMPOSITE":
            sizes = _part_sizes(s3, bucket, key)
            assert sum(sizes) == len(payload), f"part sizes {sizes!r} do not sum to {len(payload)}"
            want = _crc32_composite_by_sizes(payload, sizes) + f"-{len(sizes)}"
        else:
            want = _crc32_b64(payload)
        assert head["ChecksumCRC32"] == want, (
            f"default CRC32/{ctype} HeadObject value {head['ChecksumCRC32']!r} != computed {want!r}"
        )
        return
    if head.get("ChecksumCRC64NVME") is not None:
        assert ctype == "FULL_OBJECT", f"CRC64NVME must be FULL_OBJECT, got ChecksumType={ctype!r}"
        want = _crc64nvme_b64(payload)
        assert head["ChecksumCRC64NVME"] == want, (
            f"default CRC64NVME HeadObject value {head['ChecksumCRC64NVME']!r} != computed {want!r}"
        )
        return
    raise AssertionError(f"plain `aws s3 cp` attached no recognized checksum at all: {head!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
