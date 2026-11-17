"""get-object-attributes-multipart-etag-is-part-md5-composite."""

from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-object-attributes-multipart-etag-is-part-md5-composite"
GROUP = "state-machine"
SERVICES = ["s3"]

_PART1_LEN = 5 * 1024 * 1024  # the minimum size of a non-final part
_PART2 = bytes((i * 251 + 97) % 256 for i in range(3400))  # 3400 B filler; the last part may be any size


def _delete_bucket(client, bucket):
    """Abort open uploads, delete every version and marker, then the bucket."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-goaetag-")
    params = {"Bucket": name}
    # us-east-1 is CreateBucket's implicit default region; passing a LocationConstraint for it is rejected.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAttributes' ETag for a 2-part multipart object is md5(md5(part1)||md5(part2))+'-2',
    equal to HeadObject's ETag with its quotes stripped; the same bytes in one PUT report a bare MD5.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    multi_key = "multi.bin"
    single_key = "single.bin"

    part1 = bytes((i * 17 + 11) % 256 for i in range(_PART1_LEN))
    whole = part1 + _PART2

    up = s3.create_multipart_upload(Bucket=bucket, Key=multi_key)
    upload_id = up["UploadId"]

    def _abort():
        try:
            s3.abort_multipart_upload(Bucket=bucket, Key=multi_key, UploadId=upload_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
                raise

    ctx.on_cleanup(_abort)

    parts = []
    for number, data in ((1, part1), (2, _PART2)):
        r = s3.upload_part(Bucket=bucket, Key=multi_key, UploadId=upload_id, PartNumber=number, Body=data)
        parts.append({"PartNumber": number, "ETag": r["ETag"]})

    done = s3.complete_multipart_upload(
        Bucket=bucket, Key=multi_key, UploadId=upload_id, MultipartUpload={"Parts": parts}
    )
    composite = hashlib.md5(hashlib.md5(part1).digest() + hashlib.md5(_PART2).digest()).hexdigest() + "-2"
    assert done["ETag"] == f'"{composite}"', (
        f"CompleteMultipartUpload ETag {done['ETag']!r}; want md5(md5(p1)||md5(p2))+'-2' = {composite!r}"
    )

    head = s3.head_object(Bucket=bucket, Key=multi_key)
    assert head["ETag"] == f'"{composite}"', f"HeadObject ETag {head['ETag']!r} != {composite!r}"

    multi_attrs = s3.get_object_attributes(Bucket=bucket, Key=multi_key, ObjectAttributes=["ETag"])
    assert multi_attrs["ETag"] == composite, (
        f"GetObjectAttributes ETag {multi_attrs['ETag']!r} != md5(md5(p1)||md5(p2))+'-2' = {composite!r}"
    )
    assert multi_attrs["ETag"] == head["ETag"].strip('"'), (
        f"GetObjectAttributes ETag {multi_attrs['ETag']!r} != HeadObject ETag with quotes stripped "
        f"{head['ETag'].strip(chr(34))!r}"
    )

    # --- The identical bytes in ONE PUT: a bare MD5, differing from the multipart composite above.
    single = s3.put_object(Bucket=bucket, Key=single_key, Body=whole)
    plain = hashlib.md5(whole).hexdigest()
    assert single["ETag"] == f'"{plain}"', f"single-PUT ETag {single['ETag']!r}; want the plain MD5 {plain!r}"

    single_head = s3.head_object(Bucket=bucket, Key=single_key)
    assert single_head["ETag"] == f'"{plain}"', f"HeadObject ETag {single_head['ETag']!r} != {plain!r}"

    single_attrs = s3.get_object_attributes(Bucket=bucket, Key=single_key, ObjectAttributes=["ETag"])
    assert single_attrs["ETag"] == plain, (
        f"GetObjectAttributes ETag {single_attrs['ETag']!r} != the plain MD5 {plain!r}"
    )
    assert single_attrs["ETag"] == single_head["ETag"].strip('"'), (
        f"GetObjectAttributes ETag {single_attrs['ETag']!r} != HeadObject ETag with quotes stripped "
        f"{single_head['ETag'].strip(chr(34))!r}"
    )
    assert single_attrs["ETag"] != multi_attrs["ETag"], (
        "the single-PUT and multipart GetObjectAttributes ETags are equal; S3 ETags depend on how "
        f"an object was uploaded, not only on its bytes (both {single_attrs['ETag']!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
