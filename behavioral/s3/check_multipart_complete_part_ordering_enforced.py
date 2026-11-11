"""multipart-complete-part-ordering-enforced."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multipart-complete-part-ordering-enforced"
GROUP = "ordering"
SERVICES = ["s3"]

_PART_SIZE = 5 * 1024 * 1024  # 5 MiB minimum for a non-final multipart part


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteMultipartUpload rejects an out-of-order part list with InvalidPartOrder and a
    never-uploaded part with InvalidPart (exact messages), both parts stay listed, and the ascending,
    matching list assembles part1 + part2."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "multipart-object"

    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort_if_present(ctx, bucket, key, upload_id))

    part1_body = b"1" * _PART_SIZE
    part2_body = b"2" * (1 * 1024 * 1024)

    etag1 = s3.upload_part(Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=part1_body)["ETag"]
    etag2 = s3.upload_part(Bucket=bucket, Key=key, PartNumber=2, UploadId=upload_id, Body=part2_body)["ETag"]

    listed = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)["Parts"]
    listed_by_number = {p["PartNumber"]: p["ETag"] for p in listed}
    assert listed_by_number == {1: etag1, 2: etag2}, f"ListParts mismatch: {listed_by_number}"

    # 1) Out-of-order part list must be rejected.
    order_code, order_message = _error(
        lambda: s3.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 2, "ETag": etag2},
                    {"PartNumber": 1, "ETag": etag1},
                ]
            },
        )
    )
    assert order_code == "InvalidPartOrder", f"expected InvalidPartOrder, got {order_code!r}"
    assert order_message == "The list of parts was not in ascending order. Parts must be ordered by part number.", order_message

    # 2) A part list referencing a PartNumber that was never uploaded must be rejected.
    missing_code, missing_message = _error(
        lambda: s3.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1, "ETag": etag1},
                    {"PartNumber": 3, "ETag": '"00000000000000000000000000000000"'},
                ]
            },
        )
    )
    assert missing_code == "InvalidPart", f"expected InvalidPart, got {missing_code!r}"
    assert missing_message == "One or more of the specified parts could not be found.  The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.", missing_message

    # The upload must still be alive after both rejected attempts.
    still_listed = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)["Parts"]
    still_numbers = {p["PartNumber"] for p in still_listed}
    assert still_numbers == {1, 2}, f"expected parts {{1, 2}} still present after rejections, got {still_numbers}"

    # 3) A correctly ascending, matching part list succeeds and assembles the object.
    result = s3.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={
            "Parts": [
                {"PartNumber": 1, "ETag": etag1},
                {"PartNumber": 2, "ETag": etag2},
            ]
        },
    )
    assert result.get("Key") == key, f"expected completed object Key {key!r}, got {result.get('Key')!r}"

    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert len(body) == len(part1_body) + len(part2_body), f"unexpected assembled size {len(body)}"
    assert body[: len(part1_body)] == part1_body, "part 1 bytes not first in assembled object"
    assert body[len(part1_body) :] == part2_body, "part 2 bytes not appended in order"


def _error(fn) -> tuple:
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-s3-")
    kwargs: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _abort_if_present(ctx, bucket: str, key: str, upload_id: str) -> None:
    s3 = ctx.client("s3")
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
