"""conc-s3-conditional-writes-complete-multipart-if-none-match-rejected-when-key-appears-mid-upload."""

from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-complete-multipart-if-none-match-rejected-when-key-appears-mid-upload"
GROUP = 'conditional-rejection'
SERVICES = ['s3']

_MIB = 1024 * 1024


def _delete_bucket(s3, bucket):
    """Abort uploads, empty every version and marker, then delete the bucket (raises if it cannot)."""
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-condw-")
    params = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a region pin.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _abort_upload(s3, bucket, key, upload_id):
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchUpload":
            raise


def _start_upload(ctx, s3, bucket, key):
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort_upload(s3, bucket, key, upload_id))
    return upload_id


def _upload_parts(s3, bucket, key, upload_id, parts):
    out = []
    for n, body in enumerate(parts, start=1):
        etag = s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=n,
                              Body=body)["ETag"]
        out.append({"PartNumber": n, "ETag": etag})
    return out


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _pattern(tag, size):
    unit = hashlib.sha256(tag.encode()).digest()
    return (unit * (size // len(unit) + 1))[:size]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteMultipartUpload If-None-Match:* is evaluated at completion: a key written mid-upload
    fails 412 PreconditionFailed and survives intact; on an absent key it assembles the parts.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    part1 = _pattern("part-one", 5 * _MIB)
    part2 = _pattern("part-two-tail", 123_457)

    # --- POSITIVE CONTROL: If-None-Match:* on a key nobody created completes and assembles.
    ctrl_key = "control/assembled.bin"
    ctrl_upload = _start_upload(ctx, s3, bucket, ctrl_key)
    ctrl_parts = _upload_parts(s3, bucket, ctrl_key, ctrl_upload, [part1, part2])
    done = s3.complete_multipart_upload(
        Bucket=bucket, Key=ctrl_key, UploadId=ctrl_upload,
        MultipartUpload={"Parts": ctrl_parts}, IfNoneMatch="*",
    )
    assert done["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"If-None-Match:* completion on an absent key returned "
        f"{done['ResponseMetadata']['HTTPStatusCode']!r}, expected 200"
    )
    assembled = s3.get_object(Bucket=bucket, Key=ctrl_key)
    body = assembled["Body"].read()
    assert body == part1 + part2, (
        f"the control object is {len(body)} bytes (sha256 {hashlib.sha256(body).hexdigest()}), "
        f"want exactly part1+part2 = {len(part1) + len(part2)} bytes"
    )
    assert assembled["ETag"] == done["ETag"] and done["ETag"].endswith('-2"'), (
        f"GET ETag {assembled['ETag']!r} vs completion ETag {done['ETag']!r}; want equal and a "
        "two-part multipart ETag ending in -2"
    )

    # --- Break exactly one thing: the key is absent at initiation but EXISTS at completion.
    key = "contended/raced.bin"
    upload = _start_upload(ctx, s3, bucket, key)
    parts = _upload_parts(s3, bucket, key, upload, [part1, part2])
    interloper = b"interloper-wrote-this-while-the-multipart-upload-was-open"
    interloper_etag = s3.put_object(Bucket=bucket, Key=key, Body=interloper)["ETag"]

    exc = _client_error(lambda: s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload,
        MultipartUpload={"Parts": parts}, IfNoneMatch="*",
    ))
    assert exc is not None, (
        "CompleteMultipartUpload If-None-Match:* succeeded over a key an interloper created "
        "mid-upload; the condition was evaluated at initiation or ignored"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    message = exc.response.get("Error", {}).get("Message")
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code!r}"
    assert message == "At least one of the pre-conditions you specified did not hold", message
    assert status == 412, f"expected HTTP 412, got {status!r}"

    # --- Effect absent: the interloper's object is untouched by bytes, ETag and size.
    got = s3.get_object(Bucket=bucket, Key=key)
    now = got["Body"].read()
    assert now == interloper, (
        f"the refused completion changed the object: it is {len(now)} bytes, want the "
        f"{len(interloper)}-byte interloper payload"
    )
    assert got["ETag"] == interloper_etag, (
        f"object ETag is {got['ETag']!r}, want the interloper's {interloper_etag!r}"
    )
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] == len(interloper), (
        f"HeadObject reports {head['ContentLength']} bytes, want {len(interloper)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
