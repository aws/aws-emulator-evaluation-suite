"""s3x-s3express-session-and-listing-inflight-mpu-prefix-listed."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "s3x-s3express-session-and-listing-inflight-mpu-prefix-listed"
GROUP = 'directory_buckets'
SERVICES = ['s3']


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


def _err(fn):
    """Call fn(); return (Error.Code, HTTP status) of the ClientError. Raise if it SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
    brief = {k: v for k, v in (result or {}).items() if k not in ("ResponseMetadata", "Body")}
    raise AssertionError(f"expected the call to be refused, it succeeded: {brief!r}")


def _empty_and_delete(s3, bucket):
    """Abort every open MPU, delete every object, then delete the bucket."""
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
    return name


def _abort_upload(s3, bucket, key, upload_id):
    """Teardown for one MPU; an upload the check already aborted is not a leak."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchUpload":
            raise


def _common_prefixes(s3, bucket):
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Delimiter="/")
    return sorted(p["Prefix"] for page in pages for p in page.get("CommonPrefixes", []) or [])


def _keys(s3, bucket):
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
    return sorted(o["Key"] for page in pages for o in page.get("Contents", []) or [])


@tags("cap:c2", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """With an MPU open on ``inflight/big.bin``, a directory bucket lists ``inflight/`` as a
    CommonPrefix while a general-purpose twin does not; neither lists the key, and abort clears it.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-differences.html
    """
    s3 = ctx.client("s3")
    directory = _directory_bucket(ctx, s3, "sim2real-s3x-mpu-")
    twin = _general_purpose_bucket(ctx, s3, "sim2real-s3x-mpu-gp-")
    settled, inflight = "settled/a.txt", "inflight/big.bin"

    for bucket in (directory, twin):
        s3.put_object(Bucket=bucket, Key=settled, Body=b"settled")
        assert _common_prefixes(s3, bucket) == ["settled/"], (
            f"{bucket}: baseline prefixes {_common_prefixes(s3, bucket)!r}, expected ['settled/']"
        )

    uploads = {}
    for bucket in (directory, twin):
        up = s3.create_multipart_upload(Bucket=bucket, Key=inflight)["UploadId"]
        ctx.on_cleanup(lambda b=bucket, u=up: _abort_upload(s3, b, inflight, u))
        s3.upload_part(Bucket=bucket, Key=inflight, UploadId=up, PartNumber=1, Body=b"p" * 1024)
        uploads[bucket] = up

    # The same instant, both bucket types, identical key layout and identical open upload.
    dir_prefixes, twin_prefixes = _common_prefixes(s3, directory), _common_prefixes(s3, twin)
    assert dir_prefixes == ["inflight/", "settled/"], (
        f"directory bucket with an open MPU listed prefixes {dir_prefixes!r}, expected "
        f"['inflight/', 'settled/']"
    )
    assert twin_prefixes == ["settled/"], (
        f"general-purpose twin with an open MPU listed prefixes {twin_prefixes!r}, expected ['settled/']"
    )
    for bucket in (directory, twin):
        keys = _keys(s3, bucket)
        assert keys == [settled], f"{bucket}: the in-progress object surfaced as a key: {keys!r}"

    twin_open = [u["UploadId"] for u in s3.list_multipart_uploads(Bucket=twin, Prefix="inflight/").get("Uploads", []) or []]
    assert twin_open == [uploads[twin]], f"twin's MPU is not open as expected: {twin_open!r}"

    # Transition: abort the directory bucket's upload and its prefix goes with it.
    s3.abort_multipart_upload(Bucket=directory, Key=inflight, UploadId=uploads[directory])
    after = _common_prefixes(s3, directory)
    assert after == ["settled/"], f"after AbortMultipartUpload the directory bucket still lists {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
