"""encryption-enforcement-reject-unencrypted."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "encryption-enforcement-reject-unencrypted"
GROUP = 'auth_enforcement'
SERVICES = ['s3']

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":  # CreateBucket rejects an explicit LocationConstraint for us-east-1
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _err(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """When the bucket mandates SSE-KMS (default encryption + a policy denying writes that omit the header), a PutObject omitting it MUST be rejected.

    The write must not be silently accepted (and definitely not silently encrypted anyway).
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    # Positive control, before any enforcement exists: a plain PutObject to a fresh bucket
    # succeeds. Without this, an AccessDenied later cannot be distinguished from a bucket that
    # rejects every write for an unrelated reason.
    control_key = "control-before-policy.bin"
    s3.put_object(Bucket=bucket, Key=control_key, Body=b"baseline-write-ok")
    s3.head_object(Bucket=bucket, Key=control_key)

    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": True}]
        },
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyUnlessKmsEncrypted",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    try:
        key = "must-be-encrypted.bin"
        caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
        denied = _err(lambda: s3.put_object(Bucket=bucket, Key=key, Body=b"plaintext-attempt"))
        assert denied == (
            "AccessDenied",
            f"User: {caller_arn} is not authorized to perform: s3:PutObject on resource: "
            f'"arn:aws:s3:::{bucket}/{key}" with an explicit deny in a resource-based policy',
        ), f"expected the policy's AccessDenied for PutObject missing SSE-KMS header, got {denied}"

        # object must not exist -- the rejected write had no side effect
        # HeadObject answers with no body, so its 404 status is the whole refusal to grade
        head_err = _err(lambda: s3.head_object(Bucket=bucket, Key=key))[0]
        assert head_err == "404", (
            f"expected the rejected write to leave no object (404 on HeadObject), got {head_err}"
        )

        # a correctly-encrypted PutObject succeeds
        s3.put_object(Bucket=bucket, Key=key, Body=b"ciphertext-ok", ServerSideEncryption="aws:kms")
        head = s3.head_object(Bucket=bucket, Key=key)
        assert head.get("ServerSideEncryption") == "aws:kms", (
            f"expected the compliant PutObject to be stored as aws:kms, got {head.get('ServerSideEncryption')!r}"
        )
    finally:
        s3.delete_bucket_policy(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
