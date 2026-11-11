"""delete-object-under-retention-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-object-under-retention-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObject of a version under active GOVERNANCE retention is refused with AccessDenied and
    the version survives; with BypassGovernanceRetention (or after expiry) the delete succeeds."""

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-retention-")
    params = {"Bucket": bucket, "ObjectLockEnabledForBucket": True}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**params)
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"could not create Object-Lock-enabled bucket: {exc}")
    ctx.on_cleanup(lambda: _force_empty_and_delete_bucket(ctx, bucket))

    key = "retained-object.txt"
    version_id = s3.put_object(Bucket=bucket, Key=key, Body=b"retained-content")["VersionId"]

    retain_until = datetime.now(timezone.utc) + timedelta(seconds=20)
    s3.put_object_retention(
        Bucket=bucket,
        Key=key,
        VersionId=version_id,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until},
    )
    retention = s3.get_object_retention(Bucket=bucket, Key=key, VersionId=version_id)["Retention"]
    assert retention["Mode"] == "GOVERNANCE", f"expected GOVERNANCE mode to round-trip, got {retention['Mode']!r}"

    err = _client_error(
        lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id),
        "DeleteObject of a version under active GOVERNANCE retention",
    )["Error"]
    assert err.get("Code") == "AccessDenied", f"expected AccessDenied under active retention, got {err}"
    assert err.get("Message") == "Access Denied because object protected by object lock.", err.get("Message")

    # the forbidden effect did not happen: version still present, content intact
    body = s3.get_object(Bucket=bucket, Key=key, VersionId=version_id)["Body"].read()
    assert body == b"retained-content", f"expected the retained version's content untouched, got {body!r}"

    # positive control: an authorized bypass delete succeeds even while retention is active
    try:
        s3.delete_object(
            Bucket=bucket,
            Key=key,
            VersionId=version_id,
            BypassGovernanceRetention=True,
        )
        bypassed = True
    except Exception:  # noqa: BLE001
        bypassed = False

    if not bypassed:
        # fall back: wait out the short retention window, then a plain delete succeeds
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
                break
            except ClientError:
                time.sleep(2)
        else:
            raise AssertionError("could not remove retained version even after retention window elapsed")

    not_found = _client_error(
        lambda: s3.get_object(Bucket=bucket, Key=key, VersionId=version_id),
        "GetObject of the deleted version",
    )["Error"]
    assert not_found.get("Code") == "NoSuchVersion", f"expected NoSuchVersion after real delete, got {not_found}"
    assert not_found.get("Message") == "The specified version does not exist.", not_found.get("Message")


def _client_error(fn, what: str) -> dict:
    """Call fn(); return the ClientError response it raised. A success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"{what} succeeded; expected a refusal")


def _force_empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                key, vid = v["Key"], v["VersionId"]
                for bypass in (True, False):
                    try:
                        s3.delete_object(
                            Bucket=bucket,
                            Key=key,
                            VersionId=vid,
                            BypassGovernanceRetention=bypass,
                        )
                        break
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                            raise
                        continue
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
