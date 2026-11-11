"""representation-package-version-numeric-size-precision-preserved."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "representation-package-version-numeric-size-precision-preserved"
GROUP = "representation"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePackage's LastUpdatedAt exactly equals the version's CreatedAt in
    GetPackageVersionHistory and its CommitMessage round-trips byte-identical; after
    DeletePackage, UpdatePackage fails with ValidationException."""
    opensearch = ctx.client("opensearch")
    s3 = ctx.client("s3")

    bucket_name = f"sim2real-behav-pkgsrc-{uuid.uuid4().hex[:10]}"
    _create_bucket(ctx, s3, bucket_name)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket_name))

    s3.put_object(Bucket=bucket_name, Key="dict/v1.txt", Body=b"hello, world\nfoo, bar\n")
    s3.put_object(Bucket=bucket_name, Key="dict/v2.txt", Body=b"hello, world\nfoo, bar, baz\n")

    package_name = f"sim2real-pkg-{uuid.uuid4().hex[:10]}"

    created = opensearch.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket_name, "S3Key": "dict/v1.txt"},
    )["PackageDetails"]
    package_id = created["PackageID"]
    ctx.on_cleanup(lambda: _delete_package_ignore_missing(opensearch, package_id))
    _wait_package_terminal(ctx, opensearch, package_id)

    # Package versions expose no size field; the timestamp is the precision-bearing value.
    commit_message = "sim2real fidelity check v2 -- 0123456789.987654321"
    updated = opensearch.update_package(
        PackageID=package_id,
        PackageSource={"S3BucketName": bucket_name, "S3Key": "dict/v2.txt"},
        CommitMessage=commit_message,
    )["PackageDetails"]
    last_updated_at = updated["LastUpdatedAt"]

    entry = _find_version_history_entry(ctx, opensearch, package_id, commit_message)
    assert entry["CommitMessage"] == commit_message, (
        f"CommitMessage mangled: {entry['CommitMessage']!r} != {commit_message!r}"
    )
    assert entry["CreatedAt"] == last_updated_at, (
        f"version CreatedAt ({entry['CreatedAt']!r}) does not exactly match "
        f"UpdatePackage's LastUpdatedAt ({last_updated_at!r})"
    )

    opensearch.delete_package(PackageID=package_id)
    _wait_package_gone(ctx, opensearch, package_id)
    code, message = _error(lambda: opensearch.update_package(
        PackageID=package_id,
        PackageSource={"S3BucketName": bucket_name, "S3Key": "dict/v2.txt"},
        CommitMessage="post-delete",
    ))
    assert code == "ValidationException", (
        f"UpdatePackage on deleted package {package_id} returned {code!r}, "
        "expected ValidationException"
    )
    assert message == "Package not found.", (
        f"UpdatePackage on deleted package: expected message 'Package not found.', got {message!r}"
    )

def _create_bucket(ctx, s3, bucket_name) -> None:
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    waiter = s3.get_waiter("bucket_exists")
    waiter.wait(Bucket=bucket_name, WaiterConfig={"Delay": 2, "MaxAttempts": 50})
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
    )


def _delete_bucket(s3, bucket_name) -> None:
    objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
    for obj in objects:
        s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket_name)


def _wait_package_terminal(ctx, opensearch, package_id, timeout_s: float = 120.0) -> None:
    terminal = {"AVAILABLE", "COPY_FAILED", "VALIDATION_FAILED"}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"]
        if details and details[0]["PackageStatus"] in terminal:
            assert details[0]["PackageStatus"] == "AVAILABLE", (
                f"package {package_id} failed to become available: {details[0]}"
            )
            return
        time.sleep(5)
    raise AssertionError(f"package {package_id} never reached a terminal status within {timeout_s}s")


def _wait_package_gone(ctx, opensearch, package_id, timeout_s: float = 120.0) -> None:
    # DescribePackages either stops returning the id or leaves a DELETED tombstone
    # entry behind -- both count as gone.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"]
        if not details or details[0]["PackageStatus"] == "DELETED":
            return
        time.sleep(5)
    raise AssertionError(f"package {package_id} still listed {timeout_s}s after DeletePackage")


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected call to raise a ClientError, it succeeded")


def _delete_package_ignore_missing(opensearch, package_id) -> None:
    for _ in range(12):
        try:
            opensearch.delete_package(PackageID=package_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException"):
                return
            if code == "ConflictException":
                time.sleep(10)
                continue
            raise


def _find_version_history_entry(ctx, opensearch, package_id, commit_message, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        history = opensearch.get_package_version_history(PackageID=package_id).get(
            "PackageVersionHistoryList", []
        )
        for entry in history:
            if entry.get("CommitMessage") == commit_message:
                return entry
        time.sleep(3)
    raise AssertionError(
        f"no version history entry with CommitMessage={commit_message!r} appeared for {package_id}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

