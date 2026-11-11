"""s3x-s3express-session-and-listing-unterminated-prefix-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "s3x-s3express-session-and-listing-unterminated-prefix-rejected"
GROUP = 'directory_buckets'
SERVICES = ['s3']


# ===== helpers (self-contained) =====

# S3 Express One Zone Availability-Zone IDs per region. Zone IDs (not names) are physical and
# identical in every account, so this is a fact about AWS, not about any one account.
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
    """Call fn(); return (Error.Code, HTTP status, Error.Message) of the ClientError. Raise if it
    SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                exc.response.get("Error", {}).get("Message"))
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

# ===== end helpers =====


def _general_purpose_bucket(ctx, s3, prefix):
    name = ctx.unique_name(prefix)
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete(s3, name))
    return name


def _keys(resp):
    return sorted(o["Key"] for o in resp.get("Contents", []) or [])


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Prefix not ending in '/' is InvalidRequest (400) on an S3 Express directory bucket, with or
    without Delimiter='/', while 'k/' lists the object there and a general-purpose twin accepts and
    matches 'k': the missing terminator on a directory bucket is the cause.
    """
    s3 = ctx.client("s3")
    directory = _directory_bucket(ctx, s3, "sim2real-s3x-px-")
    twin = _general_purpose_bucket(ctx, s3, "sim2real-s3x-px-gp-")
    key = "k/obj.txt"
    for bucket in (directory, twin):
        s3.put_object(Bucket=bucket, Key=key, Body=b"prefixed")

    # Positive control: the '/'-terminated prefix lists the object on the directory bucket.
    terminated = _keys(s3.list_objects_v2(Bucket=directory, Prefix="k/"))
    assert terminated == [key], f"directory bucket Prefix='k/' returned {terminated!r}, expected [{key!r}]"

    # The one thing under test, alone and alongside the one legal delimiter.
    want = ("InvalidRequest", 400, (
        "This bucket does not support a prefix that does not end in a delimiter. Specify a prefix "
        "path ending with a delimiter and try again."
    ))
    code, status, message = _err(lambda: s3.list_objects_v2(Bucket=directory, Prefix="k"))
    assert (code, status, message) == want, (
        f"directory bucket ListObjectsV2 Prefix='k' returned {(code, status, message)!r}, "
        f"expected {want!r}"
    )
    code, status, message = _err(lambda: s3.list_objects_v2(Bucket=directory, Prefix="k", Delimiter="/"))
    assert (code, status, message) == want, (
        f"directory bucket ListObjectsV2 Prefix='k' Delimiter='/' returned "
        f"{(code, status, message)!r}, expected {want!r}"
    )

    # The identical request on the general-purpose twin is accepted and matches.
    loose = _keys(s3.list_objects_v2(Bucket=twin, Prefix="k"))
    assert loose == [key], f"twin Prefix='k' returned {loose!r}, expected [{key!r}]"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
