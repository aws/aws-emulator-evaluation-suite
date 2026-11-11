"""put-object-if-match-refuses-a-composite-etag-replaced-by-another-multipart-upload."""

from __future__ import annotations

import hashlib
import os
import secrets

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-if-match-refuses-a-composite-etag-replaced-by-another-multipart-upload"
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


def _multipart_put(ctx, s3, bucket, key, parts):
    """Upload ``parts`` as one multipart object at ``key``; return CompleteMultipartUpload's ETag."""
    upload = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort(s3, bucket, key, upload))
    done = []
    for number, body in enumerate(parts, start=1):
        etag = s3.upload_part(Bucket=bucket, Key=key, UploadId=upload, PartNumber=number, Body=body)["ETag"]
        done.append({"PartNumber": number, "ETag": etag})
    return s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload, MultipartUpload={"Parts": done}
    )["ETag"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A two-part object replaced by a three-part upload of different bytes leaves its composite
    ETag stale: PutObject If-Match on it is refused 412 PreconditionFailed and the three-part object
    survives, while If-Match on the new '-3' composite ETag replaces it.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "locked/model.bin"
    # One attempt per conditional write: a retried PUT whose first try landed would read as stale.
    once = ctx.client("s3", config=Config(retries={"total_max_attempts": 1}))

    first = [os.urandom(PART), os.urandom(1 + secrets.randbelow(4096))]
    second = [os.urandom(PART), os.urandom(PART), os.urandom(1 + secrets.randbelow(4096))]
    old = _multipart_put(ctx, s3, bucket, key, first)
    assert old == _multipart_etag(first), f"first upload ETag {old!r}, expected {_multipart_etag(first)!r}"
    new = _multipart_put(ctx, s3, bucket, key, second)
    assert new == _multipart_etag(second), f"second upload ETag {new!r}, expected {_multipart_etag(second)!r}"

    late = _refusal(lambda: once.put_object(Bucket=bucket, Key=key, Body=b"lost-update", IfMatch=old))
    want = (*PRECONDITION, 412)
    assert late == want, f"If-Match on the replaced composite ETag: expected {want!r}, got {late!r}"
    head = s3.head_object(Bucket=bucket, Key=key)
    whole = b"".join(second)
    assert (head["ETag"], head["ContentLength"]) == (new, len(whole)), (
        f"after the refusal HeadObject reports {(head['ETag'], head['ContentLength'])!r}, expected {(new, len(whole))!r}"
    )

    final = secrets.token_bytes(777)
    put = once.put_object(Bucket=bucket, Key=key, Body=final, IfMatch=new)
    final_etag = f'"{hashlib.md5(final).hexdigest()}"'
    assert put["ETag"] == final_etag, f"If-Match PutObject ETag {put['ETag']!r}, expected {final_etag!r}"
    got = s3.get_object(Bucket=bucket, Key=key)
    assert got["Body"].read() == final and got["ETag"] == final_etag, (
        "the If-Match write on the current composite ETag did not replace the object"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
