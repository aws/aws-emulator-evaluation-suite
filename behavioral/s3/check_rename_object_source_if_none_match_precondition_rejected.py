"""rename-object-source-if-none-match-precondition-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rename-object-source-if-none-match-precondition-rejected"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RenameObject with SourceIfNoneMatch='*' fails with PreconditionFailed.

    The source object stays intact and the destination key is not created.
    """
    bucket = _create_directory_bucket(ctx)
    s3 = ctx.client("s3")

    # Positive control: an unconditioned RenameObject on this bucket/session actually succeeds,
    # so the PreconditionFailed asserted below is attributable to SourceIfNoneMatch, not to
    # RenameObject being broken or unsupported here.
    ctrl_src_key = "control-src.txt"
    ctrl_dst_key = "control-dst.txt"
    ctrl_body = b"control-body"
    s3.put_object(Bucket=bucket, Key=ctrl_src_key, Body=ctrl_body)
    s3.rename_object(Bucket=bucket, Key=ctrl_dst_key, RenameSource=ctrl_src_key)
    ctx.on_cleanup(lambda: _safe(s3.delete_object, Bucket=bucket, Key=ctrl_dst_key))
    ctrl_got = s3.get_object(Bucket=bucket, Key=ctrl_dst_key)
    assert ctrl_got["Body"].read() == ctrl_body, "positive control rename did not move the body"
    ctrl_src_gone = _error(lambda: s3.get_object(Bucket=bucket, Key=ctrl_src_key))
    assert ctrl_src_gone == ("NoSuchKey", "The specified key does not exist."), (
        f"positive control rename should have removed the source key, got {ctrl_src_gone!r}"
    )

    src_key = "src-precondition.txt"
    dst_key = "dst-precondition.txt"
    body = b"do-not-rename-me"
    s3.put_object(Bucket=bucket, Key=src_key, Body=body)
    ctx.on_cleanup(lambda: _safe(s3.delete_object, Bucket=bucket, Key=src_key))

    refusal = _error(
        lambda: s3.rename_object(
            Bucket=bucket, Key=dst_key, RenameSource=src_key, SourceIfNoneMatch="*"
        )
    )
    assert refusal == (
        "PreconditionFailed", "At least one of the pre-conditions you specified did not hold"
    ), f"expected PreconditionFailed, got {refusal!r}"

    # source object must be untouched, destination must not have been created
    still_there = s3.get_object(Bucket=bucket, Key=src_key)
    assert still_there["Body"].read() == body

    dst_gone = _error(lambda: s3.get_object(Bucket=bucket, Key=dst_key))
    assert dst_gone == ("NoSuchKey", "The specified key does not exist."), f"destination should not exist, got {dst_gone!r}"


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
    ec2 = ctx.client("ec2")
    try:
        azs = ec2.describe_availability_zones(
            Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    except Exception as exc:
        raise AssertionError(f"cannot discover availability zones for S3 Express: {exc}") from exc
    zone_ids = [az["ZoneId"] for az in azs if az.get("ZoneId")]
    if not zone_ids:
        raise AssertionError("no availability-zone id discovered for S3 Express directory bucket")

    base = ctx.unique_name("sim2realdb").rstrip("-").replace("_", "-").lower()
    last_err = None
    for az_id in zone_ids:
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
        ctx.on_cleanup(lambda b=bucket: _delete_directory_bucket(s3, b))
        return bucket
    raise AssertionError(f"S3 Express directory buckets unavailable in this environment: {last_err}")


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
