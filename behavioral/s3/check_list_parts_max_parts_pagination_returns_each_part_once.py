"""list-parts-max-parts-pagination-returns-each-part-once."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-parts-max-parts-pagination-returns-each-part-once"
GROUP = "multipart"
SERVICES = ["s3"]

_PART_SIZE = 5 * 1024 * 1024  # S3 multipart minimum part size (except the last part)
_N_PARTS = 5
_MAX_PARTS = 2


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListParts with MaxParts=2 over 5 uploaded parts pages with IsTruncated and
    NextPartNumberMarker; following PartNumberMarker returns every part exactly once, in order."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "list-parts-pagination.bin"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(_teardown(
        lambda: s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id),
        "NoSuchUpload",
    ))

    uploaded = {}
    for n in range(1, _N_PARTS + 1):
        body = bytes([n]) * _PART_SIZE
        part = s3.upload_part(Bucket=bucket, Key=key, PartNumber=n, UploadId=upload_id, Body=body)
        uploaded[n] = part["ETag"]

    seen: list[int] = []
    marker = None
    truncated = True
    pages = 0
    while truncated:
        kwargs = {"Bucket": bucket, "Key": key, "UploadId": upload_id, "MaxParts": _MAX_PARTS}
        if marker is not None:
            kwargs["PartNumberMarker"] = marker
        resp = s3.list_parts(**kwargs)
        pages += 1
        assert pages <= _N_PARTS, f"pagination did not converge after {pages} pages: seen {seen!r}"
        page_numbers = [p["PartNumber"] for p in resp["Parts"]]
        assert len(page_numbers) <= _MAX_PARTS, (
            f"page returned {len(page_numbers)} parts, more than MaxParts={_MAX_PARTS}: {page_numbers!r}"
        )
        for p in resp["Parts"]:
            assert p["ETag"] == uploaded[p["PartNumber"]], (
                f"ListParts ETag {p['ETag']!r} for part {p['PartNumber']} != upload_part ETag "
                f"{uploaded[p['PartNumber']]!r}"
            )
        seen.extend(page_numbers)
        truncated = resp["IsTruncated"]
        if truncated:
            next_marker = resp.get("NextPartNumberMarker")
            assert next_marker is not None and next_marker != marker, (
                f"IsTruncated=True but NextPartNumberMarker did not advance past {marker!r}: {resp!r}"
            )
            marker = next_marker

    assert seen == list(range(1, _N_PARTS + 1)), (
        f"paginating ListParts with MaxParts={_MAX_PARTS} must return each part exactly once, in "
        f"ascending order; got {seen!r}"
    )


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-bkt-")
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
