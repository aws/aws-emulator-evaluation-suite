"""copy-object-unrecognized-checksum-algorithm-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-object-unrecognized-checksum-algorithm-rejected"
GROUP = "checksum-rejection"
SERVICES = ["s3"]

_BODY = b"the checksum algorithm on this copy is not one of the ones s3 supports"

_UNSUPPORTED_ALGORITHM = (
    "InvalidRequest",
    "Checksum algorithm provided is unsupported. Please try again with any of the valid "
    "types: [CRC32, CRC32C, CRC64NVME, MD5, SHA1, SHA256, SHA512, XXHASH128, XXHASH3, XXHASH64]",
)


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + markers), then delete it."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-behav-cpuca-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; raise naming the result on success."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """CopyObject with a ChecksumAlgorithm value outside the supported set is rejected with
    InvalidRequest naming the valid types, and creates no destination object.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="src.bin", Body=_BODY)

    expect_error(
        lambda: s3.copy_object(
            Bucket=bucket, Key="dst-bad.bin", CopySource={"Bucket": bucket, "Key": "src.bin"},
            ChecksumAlgorithm="SHA3-256",
        ),
        *_UNSUPPORTED_ALGORITHM,
    )

    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys += [o["Key"] for o in page.get("Contents", [])]
    assert keys == ["src.bin"], (
        f"the bucket holds {keys!r}; the refused copy must not have created a destination object"
    )

    # Positive control: the same copy with a supported algorithm succeeds.
    control = s3.copy_object(
        Bucket=bucket, Key="dst-ok.bin", CopySource={"Bucket": bucket, "Key": "src.bin"},
        ChecksumAlgorithm="SHA256",
    )
    assert control["CopyObjectResult"].get("ChecksumType") == "FULL_OBJECT", (
        f"the control copy reported ChecksumType {control['CopyObjectResult'].get('ChecksumType')!r}"
    )
    got = s3.get_object(Bucket=bucket, Key="dst-ok.bin")
    assert got["Body"].read() == _BODY, "the control copy's bytes differ from the source's bytes"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
