"""upload-part-of-twenty-mib-completes-and-reads-back-exactly."""

from __future__ import annotations

import hashlib
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upload-part-of-twenty-mib-completes-and-reads-back-exactly"
GROUP = "lifecycle"
SERVICES = ["s3"]

_MIB = 1024 * 1024
_PART_SIZE = 20 * _MIB
_KEY = "twenty-mib-part.bin"


def _delete_bucket(s3, bucket: str) -> None:
    """Abort open uploads, delete every object, then the bucket; tolerates only not-found."""
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchUpload"):
            raise


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UploadPart accepts a single 20 MiB part and the completed object reads back exactly.

    The part ETag is its MD5, CompleteMultipartUpload reports MD5(part MD5)-1, GetObject the bytes.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html
    """
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-mpu20-")
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    params = {"Bucket": bucket}
    # us-east-1 is the one region whose CreateBucket takes no LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)

    body = os.urandom(_PART_SIZE)
    part_md5 = hashlib.md5(body)
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=_KEY)["UploadId"]
    part = s3.upload_part(Bucket=bucket, Key=_KEY, UploadId=upload_id, PartNumber=1, Body=body)
    assert part["ETag"].strip('"') == part_md5.hexdigest(), (
        f"UploadPart ETag {part['ETag']!r} is not the part's MD5 {part_md5.hexdigest()!r}"
    )

    done = s3.complete_multipart_upload(
        Bucket=bucket,
        Key=_KEY,
        UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": part["ETag"]}]},
    )
    expected_etag = f"{hashlib.md5(part_md5.digest()).hexdigest()}-1"
    assert done["ETag"].strip('"') == expected_etag, (
        f"CompleteMultipartUpload ETag {done['ETag']!r}, expected {expected_etag!r}"
    )

    got = s3.get_object(Bucket=bucket, Key=_KEY)
    data = got["Body"].read()
    assert (got["ContentLength"], len(data)) == (_PART_SIZE, _PART_SIZE), (
        f"GetObject reported {got['ContentLength']}, returned {len(data)}, expected {_PART_SIZE}"
    )
    assert data == body, "the object read back differs from the 20 MiB part uploaded"
    assert got["ETag"].strip('"') == expected_etag, (
        f"GetObject ETag {got['ETag']!r}, expected the multipart ETag {expected_etag!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
