"""create-storage-configuration-nonexistent-bucket-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-storage-configuration-nonexistent-bucket-not-found"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStorageConfiguration succeeds for a bucket the check creates and fails ValidationException "bucket
    not found in this region" for a bucket name that does not exist."""
    client = ctx.client("ivs-realtime")
    s3 = ctx.client("s3")

    real_bucket = ctx.unique_name("sim2real-ivsrt-bucket-").lower().replace("_", "-")
    create_kwargs = {"Bucket": real_bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=real_bucket))

    storage = client.create_storage_configuration(
        name=ctx.unique_name("sim2real-storage"), s3={"bucketName": real_bucket}
    )["storageConfiguration"]
    ctx.on_cleanup(lambda: client.delete_storage_configuration(arn=storage["arn"]))
    assert storage["s3"]["bucketName"] == real_bucket, storage

    missing_bucket = ctx.unique_name("sim2real-ivsrt-missing-").lower().replace("_", "-")
    error = _client_error(
        lambda: client.create_storage_configuration(
            name=ctx.unique_name("sim2real-storage"), s3={"bucketName": missing_bucket}
        )
    )
    assert error.get("Code") == "ValidationException", error
    assert error.get("Message") == "bucket not found in this region", error


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
