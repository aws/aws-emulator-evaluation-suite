"""s3checksum-sha256-mismatch-refuses-the-overwrite-and-the-stored-bytes-survive."""

from __future__ import annotations

import base64
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3checksum-sha256-mismatch-refuses-the-overwrite-and-the-stored-bytes-survive"
GROUP = 'checksum-rejection'
SERVICES = ['s3']

_V1 = b"version-one-bytes-whose-sha256-the-service-must-compute-" * 96
_V2 = b"version-two-bytes-are-a-different-length-and-a-different-digest-" * 64


def _delete_bucket(client, bucket):
    """Abort open uploads, empty a bucket (objects + versions + markers), then delete it."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(
                    Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"]
                )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
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
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    return name


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _sha256_b64(data: bytes) -> str:
    """The base64 SHA-256 of ``data``, in the form S3 puts in ChecksumSHA256."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A BadDigest SHA256 overwrite leaves the stored bytes, length, ETag and digest intact.

    A digest checked only after committing the bytes would destroy the stored object; the same
    overwrite with the true digest then replaces both bytes and digest.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "overwrite-target.bin"

    v1_digest = _sha256_b64(_V1)
    v2_digest = _sha256_b64(_V2)
    # Well-formed SHA-256 of a different body, so only recomputing over the body can refuse it.
    wrong = _sha256_b64(_V2 + b"x")
    assert len({v1_digest, v2_digest, wrong}) == 3, (
        f"the three digests must be distinct, got {v1_digest!r} {v2_digest!r} {wrong!r}"
    )
    assert len(base64.b64decode(wrong)) == 32, (
        f"the wrong digest must still be a well-formed 32-byte SHA-256, got "
        f"{len(base64.b64decode(wrong))} bytes"
    )

    # --- Establish the object that must survive.
    first = s3.put_object(Bucket=bucket, Key=key, Body=_V1, ChecksumSHA256=v1_digest)
    assert first["ChecksumSHA256"] == v1_digest, (
        f"PutObject echoed {first['ChecksumSHA256']!r}, the client computed {v1_digest!r} with "
        f"hashlib over the same {len(_V1)} bytes"
    )
    v1_etag = first["ETag"]

    # --- Break exactly one thing: the checksum on an otherwise valid overwrite.
    exc = _client_error(
        lambda: s3.put_object(Bucket=bucket, Key=key, Body=_V2, ChecksumSHA256=wrong)
    )
    assert exc is not None, (
        f"the overwrite was accepted with ChecksumSHA256={wrong!r} for a body whose actual "
        f"SHA-256 is {v2_digest!r} — the header is stored rather than verified"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "BadDigest", f"expected BadDigest for a mismatched SHA256, got {code!r}"
    message = exc.response.get("Error", {}).get("Message")
    assert message == "The SHA256 you specified did not match the calculated checksum.", (
        f"expected the exact BadDigest message for a mismatched SHA256, got {message!r}"
    )
    assert status == 400, f"expected HTTP 400 for BadDigest, got {status!r}"

    # --- Effect absent: the object is byte-for-byte the one that was there before.
    survivor = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    body = survivor["Body"].read()
    assert body == _V1, (
        f"the refused overwrite damaged the stored object: it is now {len(body)} bytes starting "
        f"{body[:24]!r}, it must still be the {len(_V1)} bytes of version one"
    )
    assert survivor["ContentLength"] == len(_V1), (
        f"ContentLength is {survivor['ContentLength']}, the surviving object must be {len(_V1)}"
    )
    assert survivor["ChecksumSHA256"] == v1_digest, (
        f"the object now reports ChecksumSHA256={survivor['ChecksumSHA256']!r}; the refused "
        f"overwrite must leave version one's {v1_digest!r} in place"
    )
    assert survivor["ETag"] == v1_etag, (
        f"ETag changed from {v1_etag!r} to {survivor['ETag']!r} across a refused overwrite"
    )
    listed = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        listed += [(o["Key"], o["Size"]) for o in page.get("Contents", [])]
    assert listed == [(key, len(_V1))], (
        f"the bucket listing is {listed!r}; it must hold exactly the one surviving object "
        f"{(key, len(_V1))!r}"
    )

    # --- POSITIVE CONTROL: the same overwrite with V2's true digest must go through.
    second = s3.put_object(Bucket=bucket, Key=key, Body=_V2, ChecksumSHA256=v2_digest)
    assert second["ChecksumSHA256"] == v2_digest, (
        f"the accepted overwrite echoed {second['ChecksumSHA256']!r}, want {v2_digest!r}"
    )
    replaced = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    new_body = replaced["Body"].read()
    assert new_body == _V2, (
        f"after the accepted overwrite the object is {len(new_body)} bytes, want {len(_V2)}"
    )
    assert replaced["ChecksumSHA256"] == v2_digest, (
        f"the replaced object reports {replaced['ChecksumSHA256']!r}, want {v2_digest!r}"
    )
    assert _sha256_b64(new_body) == replaced["ChecksumSHA256"], (
        f"the bytes S3 returned hash to {_sha256_b64(new_body)!r} but S3 reported "
        f"{replaced['ChecksumSHA256']!r} for them"
    )
    assert replaced["ETag"] != v1_etag, (
        f"the accepted overwrite left the ETag at {v1_etag!r}; the bytes changed, so it must not"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
