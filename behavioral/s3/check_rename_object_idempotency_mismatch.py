"""rename-object-idempotency-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rename-object-idempotency-mismatch"
GROUP = "error-semantics"
SERVICES = ["s3"]

_MISMATCH_MESSAGE = (
    "Parameters on this idempotent request are inconsistent with parameters used in previous "
    "request(s)."
)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RenameObject on a directory bucket replayed with the same ClientToken and parameters succeeds as a
    no-op, while the same token with a different source/destination fails with
    IdempotentParameterMismatch and its exact message and renames nothing."""
    s3 = ctx.client("s3")
    bucket = _create_directory_bucket(ctx)

    src_key = "src-object.txt"
    dst_key_a = "dst-a.txt"
    src_key2 = "src-object-2.txt"
    dst_key_b = "dst-b.txt"
    s3.put_object(Bucket=bucket, Key=src_key, Body=b"rename-me")

    token = ctx.unique_name("tok-")[:64]

    s3.rename_object(Bucket=bucket, Key=dst_key_a, RenameSource=src_key, ClientToken=token)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=dst_key_a))

    # Confirm the rename actually happened: independent read at the destination.
    s3.head_object(Bucket=bucket, Key=dst_key_a)

    # Retry with the SAME client token and the IDENTICAL parameters: idempotent
    # no-op success, even though src_key was already consumed by the rename above.
    resp = s3.rename_object(Bucket=bucket, Key=dst_key_a, RenameSource=src_key, ClientToken=token)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected the identical-params replay to be an idempotent no-op success, "
        f"got HTTP {resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    # Retry with the SAME client token but DIFFERENT parameters (a different, still-
    # existing source and a different destination Key): must be rejected as a
    # parameter mismatch on the idempotent request, not executed. A fresh source is
    # used here specifically so the rejection cannot be confused with "source gone".
    s3.put_object(Bucket=bucket, Key=src_key2, Body=b"do-not-rename-me")
    refusal_code, refusal_message = _error(
        lambda: s3.rename_object(
            Bucket=bucket, Key=dst_key_b, RenameSource=src_key2, ClientToken=token
        )
    )
    refusal = (refusal_code, refusal_message)
    assert refusal_message == _MISMATCH_MESSAGE, f"unexpected message {refusal_message!r}"
    assert refusal_code == "IdempotentParameterMismatch", (
        f"expected IdempotentParameterMismatch reusing a client token with different "
        f"params, got {refusal!r}"
    )

    # The forbidden rename must not have happened: destination absent, source untouched.
    absent_code, absent_message = _error(lambda: s3.get_object(Bucket=bucket, Key=dst_key_b))
    absent = (absent_code, absent_message)
    assert absent_message == "The specified key does not exist.", f"unexpected message {absent_message!r}"
    assert absent_code == "NoSuchKey", (
        f"mismatched idempotent retry must not perform the rename; GetObject on {dst_key_b!r} gave {absent!r}"
    )
    s3.head_object(Bucket=bucket, Key=src_key2)  # still present, unrenamed


def _create_directory_bucket(ctx):
    """Create an S3 Express One Zone directory bucket.

    Not every AZ in a region backs S3 Express (there is no EC2 API that flags which
    ones do), so try each AZ the region has in turn rather than assuming the first
    one returned by DescribeAvailabilityZones is S3-Express-capable.
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    try:
        azs = ec2.describe_availability_zones(
            Filters=[
                {"Name": "zone-type", "Values": ["availability-zone"]},
                {"Name": "state", "Values": ["available"]},
            ]
        )["AvailabilityZones"]
    except ClientError as exc:
        raise AssertionError(f"cannot list availability zones: {exc}") from exc
    if not azs:
        raise AssertionError("no availability zones available for an S3 Express directory bucket")

    base = ctx.unique_name("sim2real").rstrip("-").replace("-", "")[:20]
    errors = []
    bucket = None
    for az in azs:
        az_id = az["ZoneId"]
        candidate = f"{base}--{az_id}--x-s3"
        try:
            s3.create_bucket(
                Bucket=candidate,
                CreateBucketConfiguration={
                    "Location": {"Name": az_id, "Type": "AvailabilityZone"},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            errors.append(f"{az_id}: {exc}")
            continue
        bucket = candidate
        break

    if bucket is None:
        raise AssertionError(
            f"S3 Express One Zone directory buckets not available in {ctx.region} "
            f"(tried {len(azs)} AZ(s)): {'; '.join(errors)}"
        )

    def _cleanup():
        try:
            resp = s3.list_objects_v2(Bucket=bucket)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
