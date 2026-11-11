"""directory-bucket-multipart-complete-etag-is-not-an-md5-composite."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "directory-bucket-multipart-complete-etag-is-not-an-md5-composite"
GROUP = "multipart-identity"
SERVICES = ["s3"]

# S3 Express One Zone Availability-Zone IDs per region. Zone IDs (not names) are physical and
# identical in every account, so this table holds for any account.
_S3EXPRESS_AZ_IDS = {
    "us-east-1": ["use1-az4", "use1-az5", "use1-az6"],
    "us-east-2": ["use2-az1", "use2-az2"],
    "us-west-2": ["usw2-az1", "usw2-az3", "usw2-az4"],
    "ap-south-1": ["aps1-az1", "aps1-az3"],
    "ap-northeast-1": ["apne1-az1", "apne1-az4"],
    "eu-central-1": ["euc1-az1", "euc1-az2"],
    "eu-west-1": ["euw1-az1", "euw1-az3"],
    "eu-north-1": ["eun1-az1", "eun1-az2", "eun1-az3"],
}

_PART1_LEN = 5 * 1024 * 1024  # the minimum size of a non-final part
_PART2 = b"final-part-" * 500  # 5500 bytes; the last part may be any size


def _empty_and_delete(s3, bucket):
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for up in page.get("Uploads", []) or []:
            s3.abort_multipart_upload(Bucket=bucket, Key=up["Key"], UploadId=up["UploadId"])
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []) or []:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _directory_bucket(ctx, s3, prefix):
    """Create an S3 Express directory bucket, registering its teardown in the same breath."""
    azs = _S3EXPRESS_AZ_IDS.get(ctx.region)
    if not azs:
        raise AssertionError(f"S3 Express One Zone AZ IDs not known for region {ctx.region!r}")
    base = ctx.unique_name(prefix)
    last = None
    for az in azs:
        name = f"{base}--{az}--x-s3"
        try:
            s3.create_bucket(
                Bucket=name,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": az},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            last = exc
            continue
        ctx.on_cleanup(lambda b=name: _empty_and_delete(s3, b))
        return name
    raise AssertionError(f"could not create a directory bucket in any of {azs!r}: {last}")


def _general_purpose_bucket(ctx, s3, prefix):
    name = ctx.unique_name(prefix)
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _abort_quietly(s3, bucket, key, upload_id):
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _complete_two_part_upload(ctx, s3, bucket, part1, part2):
    """CreateMultipartUpload, upload two parts, CompleteMultipartUpload; return its ETag."""
    up = s3.create_multipart_upload(Bucket=bucket, Key="multi.bin")
    upload_id = up["UploadId"]
    ctx.on_cleanup(lambda: _abort_quietly(s3, bucket, "multi.bin", upload_id))
    parts = []
    for number, data in ((1, part1), (2, part2)):
        r = s3.upload_part(Bucket=bucket, Key="multi.bin", UploadId=upload_id, PartNumber=number, Body=data)
        parts.append({"PartNumber": number, "ETag": r["ETag"]})
    done = s3.complete_multipart_upload(
        Bucket=bucket, Key="multi.bin", UploadId=upload_id, MultipartUpload={"Parts": parts}
    )
    return done["ETag"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A multipart upload completes on a directory bucket, but its ETag is not the
    md5(concat(part MD5s))-N composite a general-purpose bucket's multipart ETag always is."""
    s3 = ctx.client("s3")
    directory = _directory_bucket(ctx, s3, "sim2real-s3x-mpu-etag-")
    twin = _general_purpose_bucket(ctx, s3, "sim2real-s3x-mpu-etag-gp-")

    part1 = bytes((i * 7 + 3) % 251 for i in range(_PART1_LEN))
    whole = part1 + _PART2

    twin_etag = _complete_two_part_upload(ctx, s3, twin, part1, _PART2)
    composite = (
        hashlib.md5(hashlib.md5(part1).digest() + hashlib.md5(_PART2).digest()).hexdigest() + "-2"
    )
    want_twin_etag = f'"{composite}"'
    assert twin_etag == want_twin_etag, (
        f"general-purpose twin's multipart ETag was {twin_etag!r}, want the md5-composite "
        f"{want_twin_etag!r} — the control itself is broken"
    )

    dir_etag = _complete_two_part_upload(ctx, s3, directory, part1, _PART2)
    # md5(md5(part)||md5(part)) is a pure function of the bytes, independent of the bucket that
    # stored them; the twin proved it equals want_twin_etag, so a differing directory-bucket ETag
    # for the IDENTICAL bytes proves it is not the MD5-of-parts value, regardless of its shape.
    assert dir_etag != want_twin_etag, (
        f"the directory bucket's multipart ETag {dir_etag!r} equals md5(md5(p1)||md5(p2))-2 "
        f"{want_twin_etag!r} for the identical bytes; want it to differ"
    )

    head = s3.head_object(Bucket=directory, Key="multi.bin")
    assert head["ETag"] == dir_etag, f"HeadObject ETag {head['ETag']!r} != CompleteMultipartUpload's {dir_etag!r}"
    assert head["ContentLength"] == len(whole), (
        f"directory bucket multipart object is {head['ContentLength']!r} bytes, want {len(whole)}"
    )
    body = s3.get_object(Bucket=directory, Key="multi.bin")["Body"].read()
    assert body == whole, "the directory bucket's multipart object did not reassemble the parts byte-for-byte"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
