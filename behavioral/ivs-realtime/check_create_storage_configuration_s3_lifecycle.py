"""create-storage-configuration-s3-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-storage-configuration-s3-lifecycle"
GROUP = "storage-configuration"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStorageConfiguration against a real, same-region S3 bucket succeeds and the
    bucket name round-trips through Get/List; deleting it then makes it genuinely gone --
    absent from List, ResourceNotFoundException from Get, and rejected on a second delete."""
    s3 = ctx.client("s3")
    ivsrt = ctx.client("ivs-realtime")

    bucket = ctx.unique_name("sim2real-ivsrt-bucket-").lower()
    _create_bucket(ctx, s3, bucket)

    created = ivsrt.create_storage_configuration(
        name=ctx.unique_name("sim2real-ivsrt-storage-"),
        s3={"bucketName": bucket},
    )["storageConfiguration"]
    arn = created["arn"]
    state = {"deleted": False}
    ctx.on_cleanup(lambda: state["deleted"] or ivsrt.delete_storage_configuration(arn=arn))

    assert created["s3"]["bucketName"] == bucket

    fetched = ivsrt.get_storage_configuration(arn=arn)["storageConfiguration"]
    assert fetched["s3"]["bucketName"] == bucket

    arns = {c["arn"] for c in ivsrt.list_storage_configurations()["storageConfigurations"]}
    assert arn in arns

    ivsrt.delete_storage_configuration(arn=arn)
    state["deleted"] = True

    not_found_message = f"Resource: {arn} not found"
    got = _client_error(lambda: ivsrt.get_storage_configuration(arn=arn))
    assert got.get("Code") == "ResourceNotFoundException", got
    assert got.get("Message") == not_found_message, got

    arns_after_delete = {c["arn"] for c in ivsrt.list_storage_configurations()["storageConfigurations"]}
    assert arn not in arns_after_delete

    second_delete = _client_error(lambda: ivsrt.delete_storage_configuration(arn=arn))
    assert second_delete.get("Code") == "ResourceNotFoundException", second_delete
    assert second_delete.get("Message") == not_found_message, second_delete


def _create_bucket(ctx, s3, bucket):
    # S3 quirk, not a region pin: us-east-1 is the one region CreateBucket rejects an
    # explicit LocationConstraint for -- every other region requires it.
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



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
