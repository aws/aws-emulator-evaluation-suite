"""deep-s3-storage-class-multipart-class-complete-after-abort-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-multipart-class-complete-after-abort-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Multipart uploads report their class in ListMultipartUploads/ListParts and the completed
    GLACIER object refuses GetObject; an aborted upload is unlisted, NoSuchUpload, and leaves no
    object."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-mp-")
    prefix = "mpu/"
    done_key, done_class = prefix + "glacier.bin", "GLACIER"
    gone_key, gone_class = prefix + "onezone.bin", "ONEZONE_IA"
    part_body = b"p" * 2048

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    uploads = {}
    for key, sc in ((done_key, done_class), (gone_key, gone_class)):
        uid = s3.create_multipart_upload(Bucket=bucket, Key=key, StorageClass=sc)["UploadId"]
        ctx.on_cleanup(lambda k=key, u=uid: _abort_quietly(s3, bucket, k, u))
        etag = s3.upload_part(Bucket=bucket, Key=key, UploadId=uid, PartNumber=1, Body=part_body)["ETag"]
        uploads[key] = (uid, etag, sc)

    in_flight = {(u["Key"], u["UploadId"]): u.get("StorageClass") for u in _list_uploads(s3, bucket, prefix)}
    for key, (uid, _etag, sc) in uploads.items():
        assert in_flight.get((key, uid)) == sc, (
            f"ListMultipartUploads for {key}: StorageClass {in_flight.get((key, uid))!r}, expected {sc!r}; saw {in_flight!r}"
        )
        parts = s3.list_parts(Bucket=bucket, Key=key, UploadId=uid)
        assert parts.get("StorageClass") == sc, f"ListParts {key}: StorageClass {parts.get('StorageClass')!r}"
        assert [p["Size"] for p in parts.get("Parts", [])] == [len(part_body)], f"ListParts {key}: {parts.get('Parts')!r}"

    # Positive control: complete the GLACIER upload.
    uid, etag, _ = uploads[done_key]
    s3.complete_multipart_upload(Bucket=bucket, Key=done_key, UploadId=uid,
                                 MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": etag}]})
    head = s3.head_object(Bucket=bucket, Key=done_key)
    assert head.get("StorageClass") == done_class, f"completed object StorageClass {head.get('StorageClass')!r}"
    assert head.get("ContentLength") == len(part_body), f"completed object ContentLength {head.get('ContentLength')!r}"
    got, got_message = _error_code(lambda: s3.get_object(Bucket=bucket, Key=done_key))
    assert got == "InvalidObjectState", f"GetObject on completed GLACIER upload returned {got!r}"
    assert got_message == "The operation is not valid for the object's storage class", got_message

    # Break one thing: abort the ONEZONE_IA upload, then try to complete it.
    uid, etag, _ = uploads[gone_key]
    s3.abort_multipart_upload(Bucket=bucket, Key=gone_key, UploadId=uid)

    remaining = _poll(
        ctx,
        lambda: {(u["Key"], u["UploadId"]) for u in _list_uploads(s3, bucket, prefix)},
        lambda listed: (gone_key, uid) not in listed,
    )
    assert (gone_key, uid) not in remaining, f"aborted upload still listed: {remaining!r}"

    lp, lp_message = _error_code(lambda: s3.list_parts(Bucket=bucket, Key=gone_key, UploadId=uid))
    assert lp == "NoSuchUpload", f"ListParts after abort returned {lp!r}, expected NoSuchUpload"
    assert lp_message == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", lp_message
    cm, cm_message = _error_code(lambda: s3.complete_multipart_upload(
        Bucket=bucket, Key=gone_key, UploadId=uid,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": etag}]},
    ))
    assert cm == "NoSuchUpload", f"CompleteMultipartUpload after abort returned {cm!r}, expected NoSuchUpload"
    assert cm_message == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", cm_message
    # HeadObject's 404 carries no body, so there is no AWS message to assert.
    absent, _ = _error_code(lambda: s3.head_object(Bucket=bucket, Key=gone_key))
    assert absent == "404", f"HeadObject on aborted key returned {absent!r}, expected 404"

    keys = sorted(o["Key"] for o in s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", []))
    assert keys == [done_key], f"objects under {prefix}: {keys!r}, expected only the completed one"


def _list_uploads(s3, bucket: str, prefix: str) -> list:
    out = []
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket, Prefix=prefix):
        out.extend(page.get("Uploads", []))
    return out


def _poll(ctx, fn, done, timeout_s: float = 60.0):
    """Call fn() every 2 s until done(result) or a 60 s deadline capped by ctx.time_left()."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        result = fn()
        if done(result) or time.monotonic() >= deadline:
            return result
        time.sleep(2)


def _abort_quietly(s3, bucket: str, key: str, upload_id: str) -> None:
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        # Registered after the bucket teardown, so LIFO runs it while the bucket still exists;
        # an upload already completed or aborted by the check is the only expected refusal.
        if exc.response.get("Error", {}).get("Code") != "NoSuchUpload":
            raise


def _bucket_kwargs(ctx, bucket: str) -> dict:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for upload in page.get("Uploads", []):
            s3.abort_multipart_upload(Bucket=bucket, Key=upload["Key"], UploadId=upload["UploadId"])
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=bucket)


def _error_code(fn):
    """Call fn(); return its botocore (Code, Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
