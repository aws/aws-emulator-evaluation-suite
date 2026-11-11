"""rename-object-state-transition."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rename-object-state-transition"
GROUP = "state-machine"
SERVICES = ["s3"]

# S3 Express One Zone is only enabled in specific AZs per region, not every AZ EC2 reports for
# the region — discovering AZs generically (for example via ec2:DescribeAvailabilityZones)
# can pick one where a directory bucket named after that AZ ID is rejected as InvalidBucketName.
_S3EXPRESS_AZ_BY_REGION = {
    "us-east-1": ["use1-az4", "use1-az5", "use1-az6"],
    "us-east-2": ["use2-az1", "use2-az2"],
    "us-west-2": ["usw2-az1", "usw2-az3", "usw2-az4"],
    "ap-south-1": ["aps1-az1", "aps1-az3"],
    "ap-northeast-1": ["apne1-az1", "apne1-az4"],
    "eu-central-1": ["euc1-az1", "euc1-az2"],
    "eu-west-1": ["euw1-az1", "euw1-az3"],
    "eu-north-1": ["eun1-az1", "eun1-az2", "eun1-az3"],
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """RenameObject atomically moves an object: old key -> 404, new key exposes identical content/metadata."""
    bucket = _create_directory_bucket(ctx)
    s3 = ctx.client("s3")

    src_key = "src-object.txt"
    dst_key = "dst-object.txt"
    body = b"rename-me-content"
    s3.put_object(Bucket=bucket, Key=src_key, Body=body, Metadata={"purpose": "rename-test"})

    s3.rename_object(Bucket=bucket, Key=dst_key, RenameSource=src_key)

    gone = _error(lambda: s3.get_object(Bucket=bucket, Key=src_key))
    assert gone == ("NoSuchKey", "The specified key does not exist."), f"expected source key removed (NoSuchKey), got {gone!r}"

    got = s3.get_object(Bucket=bucket, Key=dst_key)
    actual_body = got["Body"].read()
    assert actual_body == body, f"expected renamed object body {body!r}, got {actual_body!r}"
    actual_meta = got.get("Metadata", {}).get("purpose")
    assert actual_meta == "rename-test", f"expected metadata purpose='rename-test' preserved after rename, got {actual_meta!r}"
    ctx.on_cleanup(lambda: _safe(s3.delete_object, Bucket=bucket, Key=dst_key))


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _safe(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_directory_bucket(ctx):
    s3 = ctx.client("s3")
    azs = _S3EXPRESS_AZ_BY_REGION.get(ctx.region)
    if not azs:
        raise AssertionError(f"no known S3 Express One Zone Availability Zone for region {ctx.region!r}")

    base = ctx.unique_name("sim2realdb").rstrip("-").replace("_", "-").lower()
    last_err = None
    for az_id in azs:
        bucket = f"{base}--{az_id}--x-s3"
        try:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": az_id},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            last_err = exc
            continue
        ctx.on_cleanup(lambda bucket=bucket: _delete_directory_bucket(s3, bucket))
        return bucket
    raise AssertionError(f"S3 Express directory buckets unavailable in {ctx.region}: {last_err}")


def _delete_directory_bucket(s3, bucket):
    try:
        listed = s3.list_objects_v2(Bucket=bucket)
        for obj in listed.get("Contents", []):
            _safe(s3.delete_object, Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    _safe(s3.delete_bucket, Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
