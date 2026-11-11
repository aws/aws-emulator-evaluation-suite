"""delete-object-under-legal-hold-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-object-under-legal-hold-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObject of a version under an Object Lock legal hold is refused with AccessDenied and
    the version survives; once the hold is turned OFF the same delete removes it."""

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-legalhold-")
    params = {"Bucket": bucket, "ObjectLockEnabledForBucket": True}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**params)
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"could not create Object-Lock-enabled bucket: {exc}")
    ctx.on_cleanup(lambda: _force_empty_and_delete_bucket(ctx, bucket))

    key = "held-object.txt"
    version_id = s3.put_object(Bucket=bucket, Key=key, Body=b"protected-content")["VersionId"]

    s3.put_object_legal_hold(
        Bucket=bucket, Key=key, VersionId=version_id, LegalHold={"Status": "ON"}
    )
    status = s3.get_object_legal_hold(Bucket=bucket, Key=key, VersionId=version_id)["LegalHold"][
        "Status"
    ]
    assert status == "ON"

    err = _error(
        lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
    )
    assert err == ("AccessDenied", "Access Denied because object protected by object lock."), (
        f"expected AccessDenied with AWS's exact message while legal hold is ON, got {err!r}"
    )

    # the forbidden effect did not happen: the version is still there, readable
    body = s3.get_object(Bucket=bucket, Key=key, VersionId=version_id)["Body"].read()
    assert body == b"protected-content"

    # release the hold, then the identical delete call succeeds and the version is gone
    s3.put_object_legal_hold(
        Bucket=bucket, Key=key, VersionId=version_id, LegalHold={"Status": "OFF"}
    )
    s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
    not_found = _error(lambda: s3.get_object(Bucket=bucket, Key=key, VersionId=version_id))
    assert not_found == ("NoSuchVersion", "The specified version does not exist."), (
        f"expected NoSuchVersion after real delete, got {not_found!r}"
    )


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return the ClientError (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _force_empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                key, vid = v["Key"], v["VersionId"]
                if v not in page.get("DeleteMarkers", []):  # a delete marker holds no legal hold
                    try:
                        s3.put_object_legal_hold(
                            Bucket=bucket, Key=key, VersionId=vid, LegalHold={"Status": "OFF"}
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                            raise
                try:
                    s3.delete_object(Bucket=bucket, Key=key, VersionId=vid)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
