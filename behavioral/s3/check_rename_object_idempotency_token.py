"""rename-object-idempotency-token."""

from __future__ import annotations
import uuid
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "rename-object-idempotency-token"
GROUP = 'directory_buckets'
SERVICES = ['s3']

_MISMATCH_MESSAGE = (
    "Parameters on this idempotent request are inconsistent with parameters used in previous "
    "request(s)."
)

# S3 Express One Zone directory buckets must be placed on a specific, AWS-assigned
# Availability Zone ID at creation time; these ids are fixed per region, not an
# account setting, so pinning them here is a contract, not a shortcut.
EXPRESS_ZONE_IDS = {
    "us-east-1": "use1-az4",
    "us-east-2": "use2-az1",
    "us-west-2": "usw2-az1",
    "ap-south-1": "aps1-az1",
    "ap-northeast-1": "apne1-az1",
    "eu-central-1": "euc1-az1",
    "eu-west-1": "euw1-az1",
    "eu-north-1": "eun1-az1",
}


def _delete_directory_bucket(client, bucket):
    """Delete every object + abort lingering multipart uploads in a directory bucket, then delete it."""
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []) or []:
                try:
                    client.delete_object(Bucket=bucket, Key=obj["Key"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        resp = client.list_multipart_uploads(Bucket=bucket)
        for u in resp.get("Uploads", []) or []:
            try:
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "NoSuchBucket",
                    "NoSuchKey",
                    "NoSuchUpload",
                ):
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_directory_bucket(ctx, s3):
    """Create an S3 Express One Zone directory bucket (non-ctx Zonal capability), register teardown."""
    zone_id = EXPRESS_ZONE_IDS.get(ctx.region)
    if not zone_id:
        raise AssertionError(f"no known S3 Express One Zone Availability Zone for region {ctx.region!r}")
    name = f"{ctx.unique_name('sim2real-dir-')}--{zone_id}--x-s3"
    try:
        s3.create_bucket(
            Bucket=name,
            CreateBucketConfiguration={
                "Location": {"Type": "AvailabilityZone", "Name": zone_id},
                "Bucket": {"Type": "Directory", "DataRedundancy": "SingleAvailabilityZone"},
            },
        )
    except Exception as exc:
        raise AssertionError(f"directory bucket creation not supported here: {exc}") from exc
    ctx.on_cleanup(lambda: _delete_directory_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Retrying RenameObject with the SAME ClientToken but a DIFFERENT request body (a different
    RenameSource) raises IdempotentParameterMismatch rather than silently replaying the first
    response or performing the new rename."""
    s3 = ctx.client("s3")
    name = _new_directory_bucket(ctx, s3)
    src1, src2, dst = "idem-src1.txt", "idem-src2.txt", "idem-dst.txt"
    s3.put_object(Bucket=name, Key=src1, Body=b"one")
    s3.put_object(Bucket=name, Key=src2, Body=b"two")
    token = str(uuid.uuid4())

    try:
        s3.rename_object(Bucket=name, Key=dst, RenameSource=src1, ClientToken=token)
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks RenameObject support: {exc}") from exc

    # Positive control, via an independent read: the first rename actually happened.
    dst_body = s3.get_object(Bucket=name, Key=dst)["Body"].read()
    assert dst_body == b"one", f"expected dst to hold src1's content after rename, got {dst_body!r}"
    src1_gone_code, src1_gone_message = _error(lambda: s3.get_object(Bucket=name, Key=src1))
    src1_gone = (src1_gone_code, src1_gone_message)
    assert src1_gone_message == "The specified key does not exist.", f"unexpected message {src1_gone_message!r}"
    assert src1_gone_code == "NoSuchKey", (
        f"expected src1 gone after rename, GetObject gave {src1_gone!r}"
    )

    refusal_code, refusal_message = _error(
        lambda: s3.rename_object(Bucket=name, Key=dst, RenameSource=src2, ClientToken=token)
    )
    refusal = (refusal_code, refusal_message)
    assert refusal_message == _MISMATCH_MESSAGE, f"unexpected message {refusal_message!r}"
    assert refusal_code == "IdempotentParameterMismatch", (
        f"expected IdempotentParameterMismatch, got {refusal!r}"
    )

    # Effect-absent, via an independent read: the mismatched retry must not have
    # performed the second rename.
    dst_body_after = s3.get_object(Bucket=name, Key=dst)["Body"].read()
    assert dst_body_after == b"one", (
        f"mismatched idempotent retry must not rename src2 over dst, got {dst_body_after!r}"
    )
    src2_body = s3.get_object(Bucket=name, Key=src2)["Body"].read()
    assert src2_body == b"two", f"src2 must remain untouched, got {src2_body!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
