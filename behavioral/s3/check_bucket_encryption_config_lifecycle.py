"""bucket-encryption-config-lifecycle."""
from __future__ import annotations
from botocore.exceptions import ClientError

CHECK = "bucket-encryption-config-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Bucket default encryption can be set, read back exactly, and removed -- reverting
    the bucket to the base SSE-S3 default-encryption configuration AWS applies to every
    bucket."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sse-")
    _create_bucket(ctx, s3, bucket)

    # S3 applies a base SSE-S3 (AES256) default encryption configuration to every new
    # bucket, so GetBucketEncryption succeeds from the start.
    default_got = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]
    default_algo = default_got["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    assert default_algo == "AES256", f"expected automatic SSE-S3 default, got {default_algo!r}"

    # Explicitly set a different configuration (SSE-KMS via the AWS managed key) so we
    # can distinguish "the automatic default" from "a configuration we set ourselves".
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
        },
    )
    got = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]
    assert len(got["Rules"]) == 1, f"expected exactly one rule, got {got['Rules']}"
    kms_algo = got["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    assert kms_algo == "aws:kms", f"expected aws:kms after PutBucketEncryption, got {kms_algo!r}"

    # Removing the explicit configuration reverts the bucket to the automatic SSE-S3
    # default rather than leaving it with no encryption configuration at all.
    s3.delete_bucket_encryption(Bucket=bucket)
    reverted = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]
    reverted_algo = reverted["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    assert reverted_algo == "AES256", f"expected revert to SSE-S3 default, got {reverted_algo!r}"


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    if getattr(ctx, "region", None) and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "audit"}]})


def _empty_and_delete_bucket(ctx, s3, name):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": d["Key"], "VersionId": d["VersionId"]} for d in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for u in s3.list_multipart_uploads(Bucket=name).get("Uploads", []):
            s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
