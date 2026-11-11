"""multipart-upload-complete."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "multipart-upload-complete"
GROUP = 'multipart'
SERVICES = ['s3']

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; only NoSuchBucket is tolerated."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    # us-east-1 is S3's one region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _err(fn):
    """Call fn(); return the ClientError response it raises. An unexpected success raises, so a
    target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _assert_error(resp, what, codes, status, message=True):
    """Grade a refusal on code + HTTP status + non-empty message (a HEAD refusal has no body)."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") in codes, f"{what}: expected code in {codes}, got {err.get('Code')!r}"
    assert got_status == status, f"{what}: expected HTTP {status}, got {got_status!r}"
    if message:
        assert err.get("Message"), f"{what}: expected a non-empty error message, got {err.get('Message')!r}"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Multipart upload: initiate, upload 2 parts, complete — object is concatenation."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "multipart/assembled.bin"
    part1 = b"A" * (5 * 1024 * 1024)  # 5 MB minimum part size
    part2 = b"B" * 1024

    mpu = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = mpu["UploadId"]

    r1 = s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=part1)
    r2 = s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=part2)

    s3.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={
            "Parts": [
                {"PartNumber": 1, "ETag": r1["ETag"]},
                {"PartNumber": 2, "ETag": r2["ETag"]},
            ]
        },
    )
    got = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert got == part1 + part2, f"assembled size {len(got)} != expected {len(part1) + len(part2)}"

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] == len(part1 + part2), (
        f"HeadObject ContentLength {head['ContentLength']} != {len(part1 + part2)}"
    )
    assert head["ETag"].endswith('-2"'), f"expected a 2-part multipart ETag ending '-2\"', got {head['ETag']!r}"

    # The completed upload id is consumed: unreadable, unlisted, and refuses new parts.
    refused = _err(lambda: s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id))
    _assert_error(
        refused,
        "ListParts on the completed upload", ("NoSuchUpload",), 404,
    )
    expected_message = "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed."
    assert refused.get("Error", {}).get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Error", {}).get("Message")!r}'
    uploads = s3.list_multipart_uploads(Bucket=bucket, Prefix=key).get("Uploads", [])
    assert all(u["UploadId"] != upload_id for u in uploads), "the completed upload is still listed by ListMultipartUploads"
    refused = _err(lambda: s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=3, Body=b"C"))
    _assert_error(
        refused,
        "UploadPart on the completed upload", ("NoSuchUpload",), 404,
    )
    expected_message = "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed."
    assert refused.get("Error", {}).get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Error", {}).get("Message")!r}'

    s3.delete_object(Bucket=bucket, Key=key)
    _assert_error(
        _err(lambda: s3.head_object(Bucket=bucket, Key=key)),
        "HeadObject after delete", ("404", "NoSuchKey"), 404, message=False,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
