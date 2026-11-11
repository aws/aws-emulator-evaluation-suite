"""multipart-upload-visible-in-list-until-complete."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "multipart-upload-visible-in-list-until-complete"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An in-progress multipart upload appears in ListMultipartUploads and disappears once completed."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mpu-")
    _create_bucket(s3, ctx, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    key = "multipart-object.bin"
    created = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = created["UploadId"]
    ctx.on_cleanup(lambda: _safe(s3.abort_multipart_upload, Bucket=bucket, Key=key, UploadId=upload_id))

    listed_during = s3.list_multipart_uploads(Bucket=bucket)
    in_progress = {(u["Key"], u["UploadId"]) for u in listed_during.get("Uploads", [])}
    assert (key, upload_id) in in_progress, f"expected in-progress upload in {in_progress}"

    body = b"a" * (5 * 1024 * 1024)
    part = s3.upload_part(Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=body)
    etag = part["ETag"]

    # part is visible via ListParts while the upload is still open
    parts = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)["Parts"]
    assert len(parts) == 1 and parts[0]["ETag"] == etag and parts[0]["PartNumber"] == 1, (
        f"expected one part (PartNumber=1, ETag={etag!r}), got {parts}"
    )

    s3.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={"Parts": [{"ETag": etag, "PartNumber": 1}]},
    )
    ctx.on_cleanup(lambda: _safe(s3.delete_object, Bucket=bucket, Key=key))

    listed_after = s3.list_multipart_uploads(Bucket=bucket)
    after = {(u["Key"], u["UploadId"]) for u in listed_after.get("Uploads", [])}
    assert (key, upload_id) not in after, f"completed upload still listed: {after}"

    obj = s3.get_object(Bucket=bucket, Key=key)
    got_body = obj["Body"].read()
    assert got_body == body, f"expected {len(body)} bytes of 'a', got {len(got_body)} bytes"
    assert obj["ContentLength"] == len(body), (
        f"expected ContentLength={len(body)}, got {obj['ContentLength']}"
    )


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _safe(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
