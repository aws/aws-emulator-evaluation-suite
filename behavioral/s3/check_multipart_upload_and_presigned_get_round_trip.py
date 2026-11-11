"""multipart-upload-and-presigned-get-round-trip."""
from __future__ import annotations

import hashlib
import os
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multipart-upload-and-presigned-get-round-trip"
GROUP = "multipart-identity"
SERVICES = ["s3"]

# Named in the failure detail when a data-plane read is not implemented.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_KEY = "multipart.bin"
_ABORTED_KEY = "aborted.bin"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A two-part upload completes with ETag md5(md5(p1)||md5(p2))-2 and reads back byte-exact
    through GetObject and a presigned GET; an aborted upload leaves no parts; delete is final."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-mpu-")
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket_if_exists(s3, bucket))

    part1 = os.urandom(5 * 1024 * 1024)
    part2 = os.urandom(1024)
    whole = part1 + part2

    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=_KEY)["UploadId"]
    assert upload_id, "CreateMultipartUpload returned an empty UploadId"
    parts = []
    for number, data in ((1, part1), (2, part2)):
        etag = s3.upload_part(Bucket=bucket, Key=_KEY, UploadId=upload_id, PartNumber=number,
                              Body=data)["ETag"]
        assert etag == f'"{hashlib.md5(data).hexdigest()}"', (
            f"part {number} ETag {etag!r} is not the MD5 of its bytes"
        )
        parts.append({"PartNumber": number, "ETag": etag})
    listed = s3.list_parts(Bucket=bucket, Key=_KEY, UploadId=upload_id).get("Parts", [])
    assert [(p["PartNumber"], p["Size"]) for p in listed] == [(1, len(part1)), (2, len(part2))], (
        f"ListParts before completion reports {[(p['PartNumber'], p['Size']) for p in listed]!r}"
    )

    done = s3.complete_multipart_upload(Bucket=bucket, Key=_KEY, UploadId=upload_id,
                                        MultipartUpload={"Parts": parts})
    composite = hashlib.md5(hashlib.md5(part1).digest() + hashlib.md5(part2).digest()).hexdigest()
    want_etag = f'"{composite}-2"'
    assert done["ETag"] == want_etag, (
        f"CompleteMultipartUpload ETag {done['ETag']!r}, expected md5 of the part MD5s {want_etag!r}"
    )

    got = s3.get_object(Bucket=bucket, Key=_KEY)
    body = got["Body"].read()
    assert got["ETag"] == want_etag, f"GetObject ETag {got['ETag']!r}, expected {want_etag!r}"
    assert body == whole, (
        f"GetObject returned {len(body)} bytes (md5 {hashlib.md5(body).hexdigest()}), expected "
        f"{len(whole)} bytes (md5 {hashlib.md5(whole).hexdigest()})"
    )

    url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": _KEY},
                                    ExpiresIn=300)
    fetched = _fetch(ctx, url)
    assert fetched == whole, (
        f"the presigned GET returned {len(fetched)} bytes "
        f"(md5 {hashlib.md5(fetched).hexdigest()}), expected the {len(whole)} uploaded bytes"
    )

    pending = s3.list_multipart_uploads(Bucket=bucket).get("Uploads", [])
    assert not pending, f"ListMultipartUploads after completion still lists {pending!r}"

    # --- A second upload, aborted: its parts are gone.
    second = s3.create_multipart_upload(Bucket=bucket, Key=_ABORTED_KEY)["UploadId"]
    s3.upload_part(Bucket=bucket, Key=_ABORTED_KEY, UploadId=second, PartNumber=1, Body=part2)
    s3.abort_multipart_upload(Bucket=bucket, Key=_ABORTED_KEY, UploadId=second)
    code, msg, status = _list_parts_error(s3, bucket, _ABORTED_KEY, second)
    assert code == "NoSuchUpload" and status == 404 and msg, (
        f"ListParts on the aborted upload answered {code!r} HTTP {status!r} message {msg!r}, "
        f"expected NoSuchUpload, 404 and a message"
    )
    assert msg == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", (
        f"expected the exact NoSuchUpload message AWS returns, got {msg!r}"
    )
    pending = s3.list_multipart_uploads(Bucket=bucket).get("Uploads", [])
    assert not pending, f"ListMultipartUploads after the abort still lists {pending!r}"
    assert _head_status(s3, bucket, _ABORTED_KEY) == 404, "the aborted upload created an object"

    # --- Delete, and the object is gone.
    s3.delete_object(Bucket=bucket, Key=_KEY)
    assert _head_status(s3, bucket, _KEY) == 404, "the deleted object still answers HeadObject"
    try:
        s3.get_object(Bucket=bucket, Key=_KEY)
        raise AssertionError("GetObject on the deleted object succeeded")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "NoSuchKey", (
            f"GetObject on the deleted object answered {e.response['Error'].get('Code')!r}"
        )
        assert e.response["Error"]["Message"] == "The specified key does not exist.", (
            f'expected the exact NoSuchKey message AWS returns, got {e.response["Error"]["Message"]!r}'
        )
    s3.delete_bucket(Bucket=bucket)
    deadline = time.monotonic() + 30
    while _head_bucket_status(s3, bucket) != 404:
        assert time.monotonic() < deadline, "the deleted bucket still answers HeadBucket"
        time.sleep(2)


def _fetch(ctx, url) -> bytes:
    """GET a presigned URL with no credentials; any transport failure is a fidelity failure."""
    import ssl

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


def _list_parts_error(s3, bucket, key, upload_id):
    try:
        s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)
        return None, None, 200
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message"), e.response["ResponseMetadata"].get("HTTPStatusCode")


def _head_status(s3, bucket, key) -> int:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return 200
    except ClientError as e:
        return e.response["ResponseMetadata"].get("HTTPStatusCode")


def _head_bucket_status(s3, bucket) -> int:
    try:
        s3.head_bucket(Bucket=bucket)
        return 200
    except ClientError as e:
        return e.response["ResponseMetadata"].get("HTTPStatusCode")


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
