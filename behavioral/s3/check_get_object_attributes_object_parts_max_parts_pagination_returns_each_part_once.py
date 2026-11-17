"""get-object-attributes-object-parts-max-parts-pagination-returns-each-part-once."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-object-attributes-object-parts-max-parts-pagination-returns-each-part-once"
GROUP = "multipart"
SERVICES = ["s3"]

_PART_SIZE = 5 * 1024 * 1024  # S3 multipart minimum part size (except the last part)
_N_PARTS = 3
_MAX_PARTS = 2


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAttributes with ObjectAttributes=['ObjectParts'] and MaxParts=2 over 3 uploaded
    parts pages with IsTruncated and NextPartNumberMarker; following PartNumberMarker returns every
    part exactly once, in order, matching the sizes and CRC32 checksums ListParts reports."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "object-parts-pagination.bin"
    upload_id = s3.create_multipart_upload(
        Bucket=bucket, Key=key, ChecksumAlgorithm="CRC32"
    )["UploadId"]
    ctx.on_cleanup(_teardown(
        lambda: s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id),
        "NoSuchUpload",
    ))

    uploaded = {}
    for n in range(1, _N_PARTS + 1):
        size = _PART_SIZE if n < _N_PARTS else 4096
        body = bytes([n]) * size
        part = s3.upload_part(
            Bucket=bucket, Key=key, PartNumber=n, UploadId=upload_id, Body=body,
            ChecksumAlgorithm="CRC32",
        )
        uploaded[n] = {
            "Size": size, "ChecksumCRC32": part["ChecksumCRC32"], "ETag": part["ETag"],
        }
    list_parts_resp = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)
    s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id,
        MultipartUpload={"Parts": [
            {"PartNumber": n, "ETag": p["ETag"], "ChecksumCRC32": p["ChecksumCRC32"]}
            for n, p in uploaded.items()
        ]},
    )
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchKey"))

    seen: list[int] = []
    sizes: dict[int, int] = {}
    checksums: dict[int, str] = {}
    marker = None
    truncated = True
    total_parts_count = None
    pages = 0
    while truncated:
        kwargs = {
            "Bucket": bucket, "Key": key, "ObjectAttributes": ["ObjectParts"],
            "MaxParts": _MAX_PARTS,
        }
        if marker is not None:
            kwargs["PartNumberMarker"] = marker
        resp = s3.get_object_attributes(**kwargs)
        pages += 1
        assert pages <= _N_PARTS, f"pagination did not converge after {pages} pages: seen {seen!r}"
        object_parts = resp["ObjectParts"]
        if total_parts_count is None:
            total_parts_count = object_parts["TotalPartsCount"]
        else:
            assert object_parts["TotalPartsCount"] == total_parts_count, (
                f"TotalPartsCount changed across pages: {total_parts_count!r} then "
                f"{object_parts['TotalPartsCount']!r}"
            )
        page_numbers = [p["PartNumber"] for p in object_parts["Parts"]]
        assert len(page_numbers) <= _MAX_PARTS, (
            f"page returned {len(page_numbers)} parts, more than MaxParts={_MAX_PARTS}: "
            f"{page_numbers!r}"
        )
        for p in object_parts["Parts"]:
            sizes[p["PartNumber"]] = p["Size"]
            checksums[p["PartNumber"]] = p["ChecksumCRC32"]
        seen.extend(page_numbers)
        truncated = object_parts["IsTruncated"]
        if truncated:
            next_marker = object_parts.get("NextPartNumberMarker")
            assert next_marker is not None and next_marker != marker, (
                f"IsTruncated=True but NextPartNumberMarker did not advance past {marker!r}: {resp!r}"
            )
            marker = next_marker

    assert seen == list(range(1, _N_PARTS + 1)), (
        f"paginating GetObjectAttributes ObjectParts with MaxParts={_MAX_PARTS} must return each "
        f"part exactly once, in ascending order; got {seen!r}"
    )
    assert total_parts_count == _N_PARTS, (
        f"TotalPartsCount must equal the {_N_PARTS} uploaded parts, got {total_parts_count!r}"
    )
    assert len(list_parts_resp["Parts"]) == _N_PARTS, (
        f"ListParts must report {_N_PARTS} parts for the completed object, got "
        f"{len(list_parts_resp['Parts'])}"
    )
    for n, expect in uploaded.items():
        assert sizes[n] == expect["Size"], (
            f"part {n}'s GetObjectAttributes Size {sizes[n]!r} != the {expect['Size']!r} byte(s) "
            f"uploaded"
        )
        assert checksums[n] == expect["ChecksumCRC32"], (
            f"part {n}'s GetObjectAttributes ChecksumCRC32 {checksums[n]!r} != UploadPart's own "
            f"{expect['ChecksumCRC32']!r}"
        )


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-goap-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
