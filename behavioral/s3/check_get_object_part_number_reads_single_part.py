"""get-object-part-number-reads-single-part."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-object-part-number-reads-single-part"
GROUP = 'multipart'
SERVICES = ['s3']

_PART1 = 5 * 1024 * 1024      # 5 MiB — the minimum size for a non-final part
_PART2 = 1 * 1024 * 1024      # 1 MiB — final part, may be smaller
_TOTAL = _PART1 + _PART2


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _abort_upload(s3, bucket, key, upload_id):
    """Abort a multipart upload; one already completed or aborted counts as done, other errors raise."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """HeadObject/GetObject with PartNumber on a two-part object return exactly that part (206, exact
    Content-Range) with PartsCount=2, a nonexistent part fails with 416 InvalidPartNumber and its exact
    message, and a plain GET returns the whole object without PartsCount."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "parted.bin"
    part1 = b"1" * _PART1
    part2 = b"2" * _PART2

    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    # Registered at creation so an upload left open by a mid-check failure is not leaked; a
    # no-op once the upload completes below.
    ctx.on_cleanup(lambda: _abort_upload(s3, bucket, key, upload_id))
    parts = []
    for number, chunk in ((1, part1), (2, part2)):
        etag = s3.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=number, Body=chunk
        )["ETag"]
        parts.append({"ETag": etag, "PartNumber": number})
    s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": parts}
    )

    # --- Control: a plain GET returns the whole object and reports no part framing.
    whole = s3.get_object(Bucket=bucket, Key=key)
    assert whole["ContentLength"] == _TOTAL, (
        f"the completed object must be {_TOTAL} bytes, got {whole['ContentLength']}"
    )
    assert whole["Body"].read() == part1 + part2, "the reassembled object body is wrong"
    assert "PartsCount" not in whole, (
        f"a whole-object GET must not report PartsCount, got {whole.get('PartsCount')!r}"
    )

    # --- HEAD PartNumber=1 is the part-discovery call: it must report the part count and the
    # FIRST part's length, not the object's length.
    head1 = s3.head_object(Bucket=bucket, Key=key, PartNumber=1)
    assert head1.get("PartsCount") == 2, (
        f"HEAD with PartNumber=1 must report PartsCount=2, got {head1.get('PartsCount')!r} — "
        "the part boundaries were not retained through CompleteMultipartUpload"
    )
    assert head1["ContentLength"] == _PART1, (
        f"HEAD with PartNumber=1 must report the part's size {_PART1}, not the object's "
        f"{_TOTAL}; got {head1['ContentLength']}"
    )
    assert head1.get("ContentRange") == f"bytes 0-{_PART1 - 1}/{_TOTAL}", (
        f"expected ContentRange 'bytes 0-{_PART1 - 1}/{_TOTAL}', got {head1.get('ContentRange')!r}"
    )

    # --- GET PartNumber=2 must return exactly the final part's bytes at the right offset.
    got2 = s3.get_object(Bucket=bucket, Key=key, PartNumber=2)
    assert got2["ResponseMetadata"]["HTTPStatusCode"] == 206, (
        f"a part-scoped GET is a partial response (206), got {got2['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert got2.get("PartsCount") == 2, f"expected PartsCount=2, got {got2.get('PartsCount')!r}"
    assert got2["ContentLength"] == _PART2, (
        f"expected the final part's size {_PART2}, got {got2['ContentLength']}"
    )
    assert got2.get("ContentRange") == f"bytes {_PART1}-{_TOTAL - 1}/{_TOTAL}", (
        f"expected ContentRange 'bytes {_PART1}-{_TOTAL - 1}/{_TOTAL}', got {got2.get('ContentRange')!r}"
    )
    body2 = got2["Body"].read()
    assert body2 == part2, (
        f"part 2 must be the {_PART2} bytes uploaded as part 2; got {len(body2)} bytes "
        f"starting {body2[:8]!r}"
    )

    # --- Break exactly one thing: a part number past the part count.
    exc = _client_error(lambda: s3.get_object(Bucket=bucket, Key=key, PartNumber=3))
    assert exc is not None, (
        "GET with PartNumber=3 on a 2-part object succeeded; PartNumber is being ignored rather "
        "than validated, so parallel-download clients get the whole object per request"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "InvalidPartNumber", (
        f"expected InvalidPartNumber for a part number past PartsCount, got {code!r}"
    )
    assert status == 416, f"expected HTTP 416 for InvalidPartNumber, got {status!r}"
    message = exc.response.get("Error", {}).get("Message")
    assert message == "The requested partnumber is not satisfiable", message

    # --- Effect absent / control still works: the rejection left the object intact.
    again = s3.get_object(Bucket=bucket, Key=key, PartNumber=1)
    assert again["Body"].read() == part1, "part 1 is no longer readable after the rejection"
    whole_len = s3.head_object(Bucket=bucket, Key=key)["ContentLength"]
    assert whole_len == _TOTAL, (
        f"the object's total length must still be {_TOTAL} after the rejected PartNumber=3 "
        f"request, got {whole_len}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
