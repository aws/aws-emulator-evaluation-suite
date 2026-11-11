"""deep-s3-storage-class-onezone-ia-intelligent-tiering-direct-put."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-onezone-ia-intelligent-tiering-direct-put"
GROUP = "storage-class"
SERVICES = ["s3"]


@tags("cap:c2", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """Directly PUT ONEZONE_IA and INTELLIGENT_TIERING objects report their class on Head, List and
    Get with bytes intact; an in-place class-only copy changes the class, keeping bytes and ETag."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-oz-")
    objects = {
        "classes/onezone.bin": ("ONEZONE_IA", b"one-zone-infrequent-access"),
        "classes/tiering.bin": ("INTELLIGENT_TIERING", b"intelligent-tiering-bytes"),
    }

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    etags = {}
    for key, (sc, body) in objects.items():
        put = s3.put_object(Bucket=bucket, Key=key, Body=body, StorageClass=sc)
        etags[key] = put["ETag"]

    listed = {o["Key"]: o for o in s3.list_objects_v2(Bucket=bucket, Prefix="classes/").get("Contents", [])}
    assert set(listed) == set(objects), f"ListObjectsV2 under classes/ returned {sorted(listed)!r}"

    for key, (sc, body) in objects.items():
        head = s3.head_object(Bucket=bucket, Key=key)
        assert head.get("StorageClass") == sc, f"HeadObject {key}: StorageClass {head.get('StorageClass')!r}, expected {sc!r}"
        assert listed[key].get("StorageClass") == sc, (
            f"ListObjectsV2 {key}: StorageClass {listed[key].get('StorageClass')!r}, expected {sc!r}"
        )
        got = s3.get_object(Bucket=bucket, Key=key)
        data = got["Body"].read()
        assert data == body, f"GetObject {key} returned {data!r}, expected {body!r}"
        assert got.get("StorageClass") == sc, f"GetObject {key}: StorageClass {got.get('StorageClass')!r}"
        assert got["ETag"] == etags[key], f"GetObject {key}: ETag {got['ETag']!r} != PutObject {etags[key]!r}"

    tiering_head = s3.head_object(Bucket=bucket, Key="classes/tiering.bin")
    assert "ArchiveStatus" not in tiering_head, (
        f"a fresh INTELLIGENT_TIERING object reported ArchiveStatus={tiering_head.get('ArchiveStatus')!r}"
    )

    # In-place class change: ONEZONE_IA -> INTELLIGENT_TIERING.
    key = "classes/onezone.bin"
    s3.copy_object(Bucket=bucket, Key=key, CopySource={"Bucket": bucket, "Key": key},
                   StorageClass="INTELLIGENT_TIERING")
    moved = s3.head_object(Bucket=bucket, Key=key)
    assert moved.get("StorageClass") == "INTELLIGENT_TIERING", (
        f"after in-place copy StorageClass was {moved.get('StorageClass')!r}, expected INTELLIGENT_TIERING"
    )
    assert moved["ETag"] == etags[key], f"in-place class change altered ETag {etags[key]!r} -> {moved['ETag']!r}"
    data = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert data == objects[key][1], f"in-place class change altered bytes to {data!r}"
    relisted = {o["Key"]: o.get("StorageClass") for o in
                s3.list_objects_v2(Bucket=bucket, Prefix="classes/").get("Contents", [])}
    assert relisted == {"classes/onezone.bin": "INTELLIGENT_TIERING",
                        "classes/tiering.bin": "INTELLIGENT_TIERING"}, f"relist after move: {relisted!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
