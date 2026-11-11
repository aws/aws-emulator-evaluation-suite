"""create-storage-configuration-invalid-bucket-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-storage-configuration-invalid-bucket-name-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStorageConfiguration rejects a bucket name with characters outside the S3
    bucket-name pattern, while a real bucket succeeds (positive control); the rejected
    attempt leaves no storage configuration behind (independent read)."""
    s3 = ctx.client("s3")
    ivsrt = ctx.client("ivs-realtime")

    bucket = ctx.unique_name("sim2real-ivsrt-bucket-").lower()
    _create_bucket(ctx, s3, bucket)

    ok = ivsrt.create_storage_configuration(
        name=ctx.unique_name("sim2real-ivsrt-storage-"),
        s3={"bucketName": bucket},
        tags={"sim2real": CHECK},
    )["storageConfiguration"]
    ctx.on_cleanup(lambda: ivsrt.delete_storage_configuration(arn=ok["arn"]))
    assert ok["s3"]["bucketName"] == bucket, (
        f"positive control: expected bucketName {bucket!r}, got {ok['s3']['bucketName']!r}"
    )

    rejected_name = ctx.unique_name("sim2real-ivsrt-storage-")
    error = _client_error(
        lambda: ivsrt.create_storage_configuration(
            name=rejected_name,
            s3={"bucketName": "Invalid_Bucket_Name!"},
            tags={"sim2real": CHECK},
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for an invalid bucket name, got {error!r}"
    )
    assert error.get("Message") == (
        "CreateStorageConfiguration.s3.bucketName does not match the required pattern ^[a-z0-9-.]+$"
    ), error
    assert not _storage_config_named(ivsrt, rejected_name), (
        f"a storage configuration named {rejected_name!r} exists despite the rejected create"
    )


def _create_bucket(ctx, s3, bucket):
    # us-east-1 is S3's own API quirk: CreateBucketConfiguration/LocationConstraint must be
    # omitted there or the call is rejected -- not an assumption about the target's home region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



def _storage_config_named(ivsrt, name):
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = ivsrt.list_storage_configurations(**kwargs)
        if any(c["name"] == name for c in page["storageConfigurations"]):
            return True
        token = page.get("nextToken")
        if not token:
            return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
