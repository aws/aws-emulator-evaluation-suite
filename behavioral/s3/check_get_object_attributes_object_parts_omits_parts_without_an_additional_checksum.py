"""get-object-attributes-object-parts-omits-parts-without-an-additional-checksum."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-object-attributes-object-parts-omits-parts-without-an-additional-checksum"
GROUP = "multipart"
SERVICES = ["s3"]

_PART_SIZE = 5 * 1024 * 1024  # S3 multipart minimum part size (except the last part)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAttributes's ObjectParts carries TotalPartsCount for every multipart object, but
    its per-part Parts list is populated only when the upload requested an additional checksum
    (CRC32/CRC32C/SHA1/SHA256); without one, Parts is empty even though the parts exist."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    plain_parts = _upload_two_parts(s3, bucket, "no-checksum.bin", ctx, checksum_algorithm=None)
    checked_parts = _upload_two_parts(s3, bucket, "crc32-checksum.bin", ctx, checksum_algorithm="CRC32")

    plain_attrs = s3.get_object_attributes(
        Bucket=bucket, Key="no-checksum.bin", ObjectAttributes=["ObjectParts"]
    )["ObjectParts"]
    assert plain_attrs["TotalPartsCount"] == len(plain_parts), (
        f"TotalPartsCount must count the {len(plain_parts)} uploaded parts even with no additional "
        f"checksum, got {plain_attrs['TotalPartsCount']!r}"
    )
    assert plain_attrs.get("Parts", []) == [], (
        f"ObjectParts.Parts must be empty for a multipart upload with no additional checksum, got "
        f"{plain_attrs.get('Parts')!r}"
    )

    checked_attrs = s3.get_object_attributes(
        Bucket=bucket, Key="crc32-checksum.bin", ObjectAttributes=["ObjectParts"]
    )["ObjectParts"]
    assert checked_attrs["TotalPartsCount"] == len(checked_parts), (
        f"TotalPartsCount must count the {len(checked_parts)} uploaded parts, got "
        f"{checked_attrs['TotalPartsCount']!r}"
    )
    reported = {p["PartNumber"]: p for p in checked_attrs.get("Parts", [])}
    assert set(reported) == set(checked_parts), (
        f"ObjectParts.Parts must list every part {sorted(checked_parts)!r} once the upload carried "
        f"a CRC32 checksum, got {sorted(reported)!r}"
    )
    for n, expect in checked_parts.items():
        assert reported[n]["ChecksumCRC32"] == expect["ChecksumCRC32"], (
            f"part {n}'s GetObjectAttributes ChecksumCRC32 {reported[n]['ChecksumCRC32']!r} != "
            f"UploadPart's own {expect['ChecksumCRC32']!r}"
        )
        assert reported[n]["Size"] == expect["Size"], (
            f"part {n}'s GetObjectAttributes Size {reported[n]['Size']!r} != the "
            f"{expect['Size']!r} byte(s) uploaded"
        )


def _upload_two_parts(s3, bucket, key, ctx, *, checksum_algorithm):
    """Upload a 2-part object (``checksum_algorithm`` or none) and return each part's size/checksum."""
    create_kwargs = {"Bucket": bucket, "Key": key}
    if checksum_algorithm is not None:
        create_kwargs["ChecksumAlgorithm"] = checksum_algorithm
    upload_id = s3.create_multipart_upload(**create_kwargs)["UploadId"]
    ctx.on_cleanup(_teardown(
        lambda: s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id),
        "NoSuchUpload",
    ))

    sizes = {1: _PART_SIZE, 2: 4096}
    uploaded = {}
    parts_for_complete = []
    for n, size in sizes.items():
        part_kwargs = {
            "Bucket": bucket, "Key": key, "PartNumber": n, "UploadId": upload_id,
            "Body": bytes([n]) * size,
        }
        if checksum_algorithm is not None:
            part_kwargs["ChecksumAlgorithm"] = checksum_algorithm
        part = s3.upload_part(**part_kwargs)
        entry = {"Size": size}
        if checksum_algorithm is not None:
            entry["ChecksumCRC32"] = part["ChecksumCRC32"]
        uploaded[n] = entry
        completed_part = {"PartNumber": n, "ETag": part["ETag"]}
        if checksum_algorithm is not None:
            completed_part["ChecksumCRC32"] = part["ChecksumCRC32"]
        parts_for_complete.append(completed_part)

    s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id,
        MultipartUpload={"Parts": parts_for_complete},
    )
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchKey"))
    return uploaded


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-goapc-")
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
