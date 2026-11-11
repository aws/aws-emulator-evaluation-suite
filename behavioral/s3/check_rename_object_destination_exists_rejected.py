"""rename-object-destination-exists-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rename-object-destination-exists-rejected"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RenameObject with If-None-Match: * succeeds onto an absent destination, fails with
    PreconditionFailed and its exact message when the destination exists (both objects untouched), and
    succeeds once the destination is removed."""
    s3 = ctx.client("s3")
    bucket = _create_directory_bucket(ctx)

    source_key = "source-for-clash.txt"
    dest_key = "existing-destination.txt"
    source_body = b"source content"
    dest_body = b"pre-existing destination content"

    # Positive control: the same guarded rename succeeds when the destination does not exist yet,
    # so a later rejection is attributable to the clash and not to a broken RenameObject wiring.
    control_source_key = "control-source-for-clash.txt"
    control_body = b"control source content"
    s3.put_object(Bucket=bucket, Key=control_source_key, Body=control_body)
    s3.rename_object(
        Bucket=bucket,
        Key=dest_key,
        RenameSource=control_source_key,
        DestinationIfNoneMatch="*",
    )
    head_control = s3.head_object(Bucket=bucket, Key=dest_key)
    assert head_control["ContentLength"] == len(control_body), (
        f"positive control: expected the guarded rename onto a fresh destination to succeed and "
        f"land {len(control_body)} bytes, got {head_control['ContentLength']}"
    )

    # Break exactly one thing: put_source/put_dest give dest_key real, pre-existing content, which
    # is the clash the guard exists to detect.
    put_source = s3.put_object(Bucket=bucket, Key=source_key, Body=source_body)
    put_dest = s3.put_object(Bucket=bucket, Key=dest_key, Body=dest_body)

    code = _error_code(
        lambda: s3.rename_object(
            Bucket=bucket,
            Key=dest_key,
            RenameSource=source_key,
            DestinationIfNoneMatch="*",
        )
    )
    assert code == ("PreconditionFailed", "At least one of the pre-conditions you specified did not hold"), f"expected PreconditionFailed, got {code}"

    # both objects must be untouched by the rejected rename
    head_source = s3.head_object(Bucket=bucket, Key=source_key)
    assert head_source["ETag"] == put_source["ETag"], (
        f"source ETag changed across a rejected rename: expected {put_source['ETag']!r}, "
        f"got {head_source['ETag']!r}"
    )
    assert head_source["ContentLength"] == len(source_body), (
        f"source length changed across a rejected rename: expected {len(source_body)}, "
        f"got {head_source['ContentLength']}"
    )

    head_dest = s3.head_object(Bucket=bucket, Key=dest_key)
    assert head_dest["ETag"] == put_dest["ETag"], (
        f"destination ETag changed across a rejected rename: expected {put_dest['ETag']!r}, "
        f"got {head_dest['ETag']!r}"
    )
    assert head_dest["ContentLength"] == len(dest_body), (
        f"destination length changed across a rejected rename: expected {len(dest_body)}, "
        f"got {head_dest['ContentLength']}"
    )

    # Restore: remove the clashing destination, then replay the IDENTICAL call. Real AWS's own
    # guard, not this check, decides whether the rename may now proceed.
    s3.delete_object(Bucket=bucket, Key=dest_key)
    s3.rename_object(
        Bucket=bucket,
        Key=dest_key,
        RenameSource=source_key,
        DestinationIfNoneMatch="*",
    )
    head_after_restore = s3.head_object(Bucket=bucket, Key=dest_key)
    assert head_after_restore["ContentLength"] == len(source_body), (
        f"after removing the clashing destination, the identical rename should have landed "
        f"{len(source_body)} source bytes, got {head_after_restore['ContentLength']}"
    )
    source_gone_code = _error_code(lambda: s3.head_object(Bucket=bucket, Key=source_key))
    assert source_gone_code == ("404", "Not Found"), (
        f"the successful rename should have consumed the source key, but head_object on "
        f"{source_key!r} returned {source_gone_code}"
    )


def _cleanup_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_directory_bucket(ctx) -> str:
    """Create an S3 Express One Zone directory bucket, trying each AZ in the region.
    Raises if directory buckets aren't supported here."""
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    try:
        ec2 = ctx.client("ec2")
        zones = ec2.describe_availability_zones(
            Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    except ClientError as e:
        raise AssertionError(
            f"cannot enumerate availability zones: {e.response['Error']['Code']}"
        ) from e

    base = ctx.unique_name("sim2real-db-").lower()
    last_err = None
    for az in zones:
        zone_id = az["ZoneId"]
        bucket = f"{base}--{zone_id}--x-s3"
        try:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": zone_id},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
            ctx.on_cleanup(lambda b=bucket: _cleanup_bucket(ctx, b))
            return bucket
        except ClientError as e:
            last_err = e
            continue
    raise AssertionError(f"directory buckets unavailable in region {ctx.region}: {last_err}")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        resp = e.response
        status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
        code = resp["Error"]["Code"]
        return (code if code and code != "Unknown" else str(status)), resp["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
