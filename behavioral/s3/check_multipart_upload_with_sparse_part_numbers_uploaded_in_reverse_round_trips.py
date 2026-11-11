"""multipart-upload-with-sparse-part-numbers-uploaded-in-reverse-round-trips."""
from __future__ import annotations

import hashlib
import os
import secrets
import ssl
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multipart-upload-with-sparse-part-numbers-uploaded-in-reverse-round-trips"
GROUP = "multipart-identity"
SERVICES = ["s3"]

# Named in the failure detail when a data-plane read is not implemented.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_MIB = 1024 * 1024


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Three parts with gapped random part numbers, uploaded highest first, complete in part-number
    order: the object is their concatenation in that order, its ETag the MD5 of the part MD5s with
    '-3', and GetObject, HeadObject and a presigned GET agree on bytes, size and ETag."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-mpu-")
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket_if_exists(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    key = "uploads/sparse parts/archive.tar"

    numbers = sorted(secrets.SystemRandom().sample(range(2, 10000), 3))
    sizes = [5 * _MIB + 1 + secrets.randbelow(4096), 5 * _MIB, 1 + secrets.randbelow(70000)]
    data = {n: os.urandom(s) for n, s in zip(numbers, sizes, strict=True)}

    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort(s3, bucket, key, upload_id))
    etags = {}
    for number in reversed(numbers):
        etag = s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=number,
                              Body=data[number])["ETag"]
        assert etag == f'"{hashlib.md5(data[number]).hexdigest()}"', (
            f"part {number} ETag {etag!r} is not the MD5 of its bytes"
        )
        etags[number] = etag
    listed = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id).get("Parts", [])
    got = [(p["PartNumber"], p["Size"], p["ETag"]) for p in listed]
    want = [(n, len(data[n]), etags[n]) for n in numbers]
    assert got == want, f"ListParts reports {got!r}, expected ascending {want!r}"

    done = s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": n, "ETag": etags[n]} for n in numbers]},
    )
    composite = hashlib.md5(b"".join(hashlib.md5(data[n]).digest() for n in numbers)).hexdigest()
    want_etag = f'"{composite}-3"'
    assert done["ETag"] == want_etag, f"CompleteMultipartUpload ETag {done['ETag']!r}, expected {want_etag!r}"
    whole = b"".join(data[n] for n in numbers)

    head = s3.head_object(Bucket=bucket, Key=key)
    assert (head["ETag"], head["ContentLength"]) == (want_etag, len(whole)), (
        f"HeadObject (ETag, ContentLength) {(head['ETag'], head['ContentLength'])!r}, expected "
        f"{(want_etag, len(whole))!r}"
    )
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert body == whole, (
        f"GetObject returned {len(body)} bytes (md5 {hashlib.md5(body).hexdigest()}), expected the parts "
        f"in part-number order: {len(whole)} bytes (md5 {hashlib.md5(whole).hexdigest()})"
    )
    url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=300)
    fetched = _fetch(ctx, url)
    assert fetched == whole, f"the presigned GET returned {len(fetched)} bytes, expected the {len(whole)} assembled bytes"
    pending = s3.list_multipart_uploads(Bucket=bucket).get("Uploads", [])
    assert not pending, f"ListMultipartUploads after completion still lists {len(pending)} upload(s)"


def _fetch(ctx, url) -> bytes:
    """GET a presigned URL with no credentials; any transport failure is a fidelity failure."""
    verify = ctx.http_verify
    context = ssl.create_default_context(cafile=verify) if isinstance(verify, str) else None
    try:
        with urllib.request.urlopen(url, timeout=60, context=context) as resp:
            status = resp.status
            data = resp.read()
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # includes HTTPError: the URL did not serve
        raise AssertionError(
            f"{DATAPLANE_MARKER}: the presigned GET URL did not serve the object: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    assert status == 200, f"the presigned GET answered HTTP {status}"
    return data


def _abort(s3, bucket, key, upload_id) -> None:
    """Abort the upload; one already completed or aborted is gone, anything else raises."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchUpload", "NoSuchBucket"):
            raise


def _delete_bucket_if_exists(s3, bucket) -> None:
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
