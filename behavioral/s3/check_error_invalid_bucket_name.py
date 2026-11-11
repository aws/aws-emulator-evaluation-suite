"""error-invalid-bucket-name."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-invalid-bucket-name"
GROUP = 'errors'
SERVICES = ['s3']

ERR_INVALID_BUCKET_NAME = "InvalidBucketName"


def _err(fn, what):
    """Call fn(); return the botocore Error dict it raised. A success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"{what} succeeded; expected a refusal")


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBucket with uppercase letters in the name is rejected with InvalidBucketName and its exact
    message, while a valid name is created and visible to an independent read."""
    s3 = ctx.client("s3")

    good_name = ctx.unique_name("sim2real-behav-s3fid-")
    good_params: dict = {"Bucket": good_name}
    # us-east-1 rejects an explicit LocationConstraint for its own region.
    if ctx.region != "us-east-1":
        good_params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**good_params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, good_name))
    s3.head_bucket(Bucket=good_name)  # independent read: the control bucket really exists

    invalid_name = good_name.upper()
    # Only does anything if the create below unexpectedly lands.
    ctx.on_cleanup(lambda: _delete_bucket(s3, invalid_name))

    invalid_params: dict = {"Bucket": invalid_name}
    if ctx.region != "us-east-1":
        invalid_params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}

    err = _err(
        lambda: s3.create_bucket(**invalid_params),
        f"CreateBucket with an uppercase bucket name (bucket={invalid_name!r})",
    )
    assert err.get("Code") == ERR_INVALID_BUCKET_NAME, (
        f"expected {ERR_INVALID_BUCKET_NAME} for an uppercase bucket name, got {err!r}"
    )
    assert err.get("Message") == "The specified bucket is not valid.", err.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
