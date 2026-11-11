"""presigned-upload-part-urls-assemble-a-multipart-object-read-by-presigned-ranged-get."""
from __future__ import annotations

import hashlib
import os
import secrets
import ssl
import urllib.error
import urllib.request

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "presigned-upload-part-urls-assemble-a-multipart-object-read-by-presigned-ranged-get"
GROUP = "multipart-identity"
SERVICES = ["s3"]

# Named in the failure detail when a data-plane request is not implemented.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_MIB = 1024 * 1024


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Parts PUT with no credentials to presigned UploadPart URLs return their MD5 ETags and
    complete into an object with the composite '-2' ETag; a presigned GET with a Range header
    returns 206 and exactly the addressed bytes spanning the part boundary.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html
    """
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-mpu-")
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket_if_exists(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    key = "browser/upload.bin"
    # SigV4 path-style presigning addresses the bucket on the regional host the client targets.
    signer = ctx.client("s3", config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))

    parts = [os.urandom(5 * _MIB + secrets.randbelow(2048)), os.urandom(1 + secrets.randbelow(9000))]
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort(s3, bucket, key, upload_id))
    done = []
    for number, data in enumerate(parts, start=1):
        url = signer.generate_presigned_url(
            "upload_part",
            Params={"Bucket": bucket, "Key": key, "UploadId": upload_id, "PartNumber": number},
            ExpiresIn=300,
        )
        status, headers, _ = _request(ctx, url, "PUT", data=data)
        assert status == 200, f"presigned UploadPart {number} answered HTTP {status}"
        etag = headers.get("ETag")
        assert etag == f'"{hashlib.md5(data).hexdigest()}"', (
            f"presigned UploadPart {number} ETag {etag!r} is not the MD5 of its bytes"
        )
        done.append({"PartNumber": number, "ETag": etag})
    listed = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id).get("Parts", [])
    got = [(p["PartNumber"], p["Size"]) for p in listed]
    assert got == [(1, len(parts[0])), (2, len(parts[1]))], f"ListParts reports {got!r}"

    completed = s3.complete_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id,
                                             MultipartUpload={"Parts": done})
    composite = hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest()
    want_etag = f'"{composite}-2"'
    assert completed["ETag"] == want_etag, f"CompleteMultipartUpload ETag {completed['ETag']!r}, expected {want_etag!r}"
    whole = parts[0] + parts[1]

    start = len(parts[0]) - 1 - secrets.randbelow(100)
    end = len(parts[0]) + secrets.randbelow(len(parts[1]))
    url = signer.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=300)
    status, headers, body = _request(ctx, url, "GET", headers={"Range": f"bytes={start}-{end}"})
    assert status == 206, f"presigned ranged GET answered HTTP {status}, expected 206"
    assert headers.get("Content-Range") == f"bytes {start}-{end}/{len(whole)}", (
        f"presigned ranged GET Content-Range {headers.get('Content-Range')!r}, expected "
        f"'bytes {start}-{end}/{len(whole)}'"
    )
    assert body == whole[start:end + 1], (
        f"presigned ranged GET bytes={start}-{end} returned {len(body)} bytes, not the {end - start + 1} addressed"
    )
    got = s3.get_object(Bucket=bucket, Key=key)
    data = got["Body"].read()
    seen = (len(data), hashlib.md5(data).hexdigest(), got["ETag"])
    want = (len(whole), hashlib.md5(whole).hexdigest(), want_etag)
    assert seen == want, f"GetObject reads (len, md5, ETag) {seen!r}, expected the assembled object's {want!r}"


def _request(ctx, url, method, data=None, headers=None):
    """(status, headers, body) of an unauthenticated request to a presigned URL; a transport failure
    or an HTTP error status is a fidelity failure."""
    verify = ctx.http_verify
    context = ssl.create_default_context(cafile=verify) if isinstance(verify, str) else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=120, context=context) as resp:
            return resp.status, resp.headers, resp.read()
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # includes HTTPError
        raise AssertionError(
            f"{DATAPLANE_MARKER}: the presigned {method} URL did not serve: {type(exc).__name__}: {exc}"
        ) from exc


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
