"""put-object-if-match-takes-a-multipart-etag-and-refuses-it-once-stale."""

from __future__ import annotations

import hashlib

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-if-match-takes-a-multipart-etag-and-refuses-it-once-stale"
GROUP = "conditional"
SERVICES = ["s3"]

PART = 5 * 1024 * 1024
PRECONDITION = ("PreconditionFailed", "At least one of the pre-conditions you specified did not hold")


def _delete_bucket(client, bucket):
    """Empty a bucket (uploads, objects, versions, delete markers) then delete it; raises unless gone."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket, register empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _refusal(fn):
    """(Error.Code, Error.Message, HTTP status) of the ClientError ``fn`` raises; FAILS on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"the call SUCCEEDED where real AWS refuses it: {result!r}")


def _abort(s3, bucket, key, upload):
    """Abort ``upload``; one already completed or aborted is gone, anything else raises."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchUpload", "NoSuchBucket"):
            raise


def _multipart_etag(parts):
    """The ETag S3 gives a multipart object: MD5 of the parts' binary MD5s, then '-<count>'."""
    digest = hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest()
    return f'"{digest}-{len(parts)}"'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject If-Match accepts a multipart object's composite ETag and replaces it; the same
    ETag, stale after that write, is refused 412 PreconditionFailed and the newer bytes survive.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "locked/state.bin"

    parts = [b"a" * PART, b"b" * 1024]
    upload = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort(s3, bucket, key, upload))
    done = []
    for number, body in enumerate(parts, start=1):
        etag = s3.upload_part(Bucket=bucket, Key=key, UploadId=upload, PartNumber=number, Body=body)["ETag"]
        done.append({"PartNumber": number, "ETag": etag})
    completed = s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload, MultipartUpload={"Parts": done}
    )
    composite = _multipart_etag(parts)
    assert completed["ETag"] == composite, (
        f"CompleteMultipartUpload ETag {completed['ETag']!r}, expected the composite {composite!r}"
    )
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ETag"] == composite, f"HeadObject ETag {head['ETag']!r}, expected {composite!r}"

    # One attempt per conditional write: a retried PUT whose first try landed would read as stale.
    once = ctx.client("s3", config=Config(retries={"total_max_attempts": 1}))

    # The writer holding the composite ETag wins: If-Match on it replaces the object.
    first = b"written-under-the-composite-etag"
    put = once.put_object(Bucket=bucket, Key=key, Body=first, IfMatch=composite)
    first_etag = f'"{hashlib.md5(first).hexdigest()}"'
    assert put["ETag"] == first_etag, f"PutObject ETag {put['ETag']!r}, expected the MD5 {first_etag!r}"
    got = s3.get_object(Bucket=bucket, Key=key)
    assert got["Body"].read() == first, "GetObject did not return the bytes the If-Match write stored"
    assert got["ETag"] == first_etag, f"GetObject ETag {got['ETag']!r}, expected {first_etag!r}"

    # A second writer still holding the composite ETag is now stale: refused, nothing replaced.
    late = _refusal(
        lambda: once.put_object(Bucket=bucket, Key=key, Body=b"lost-update", IfMatch=composite)
    )
    want = (*PRECONDITION, 412)
    assert late == want, f"a stale If-Match PutObject: expected {want!r}, got {late!r}"
    after = s3.get_object(Bucket=bucket, Key=key)
    assert after["Body"].read() == first, "the refused stale write replaced the object"
    assert after["ETag"] == first_etag, (
        f"after the refusal the ETag is {after['ETag']!r}, expected {first_etag!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
