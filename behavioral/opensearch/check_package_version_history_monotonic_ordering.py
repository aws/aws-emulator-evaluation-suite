"""package-version-history-monotonic-ordering."""
from __future__ import annotations

import time
import uuid
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "package-version-history-monotonic-ordering"
GROUP = "ordering"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated UpdatePackage calls yield GetPackageVersionHistory entries in monotonic time order
    matching the call order, each unicode CommitMessage round-tripping byte-for-byte; the
    package is then deleted and must disappear."""
    opensearch = ctx.client("opensearch")
    s3 = ctx.client("s3")

    bucket = _short_name("sim2real-ospkg-", 45)
    _create_bucket(ctx, s3, bucket)

    # seed the initial package source object plus one object per later revision
    keys = [f"dict-v{i}.txt" for i in range(4)]
    for i, key in enumerate(keys):
        s3.put_object(Bucket=bucket, Key=key, Body=f"term-{i}-alpha\nterm-{i}-beta\n".encode())

    package_name = _short_name("sim2real-pkg-", 60)
    created = opensearch.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": keys[0]},
    )
    package_id = created["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _delete_package(opensearch, package_id))

    _wait_package_available(opensearch, package_id)

    update_messages = ["update-1", "caf\u00e9-update-2 \u2603", "update-3-\u65e5\u672c\u8a9e-\U0001f680"]
    for i, message in enumerate(update_messages, start=1):
        opensearch.update_package(
            PackageID=package_id,
            PackageSource={"S3BucketName": bucket, "S3Key": keys[i]},
            CommitMessage=message,
        )
        _wait_package_available(opensearch, package_id)

    history = opensearch.get_package_version_history(PackageID=package_id)[
        "PackageVersionHistoryList"
    ]
    assert len(history) == 1 + len(update_messages), (
        f"expected {1 + len(update_messages)} version history entries "
        f"(1 initial + {len(update_messages)} updates), got {len(history)}"
    )

    # The API's array order is a monotonic function of CreatedAt, ascending or descending, and the
    # commits follow call order along that direction. Revisions created inside one timestamp tick
    # share a CreatedAt, so the direction comes from the commit sequence, not from a sort.
    created_ats = [entry["CreatedAt"] for entry in history]
    ascending = sorted(created_ats)
    descending = sorted(created_ats, reverse=True)
    assert created_ats in (ascending, descending), (
        "GetPackageVersionHistory did not return entries in a stable chronological order: "
        f"{created_ats}"
    )

    updates_listed = [entry for entry in history if entry.get("CommitMessage") in update_messages]
    commit_sequence = [entry["CommitMessage"] for entry in updates_listed]
    if commit_sequence == update_messages:
        assert created_ats == ascending, f"commits list in call order but CreatedAt descends: {created_ats}"
        by_time = updates_listed
    else:
        assert commit_sequence == update_messages[::-1], (
            f"commit messages are not in the order UpdatePackage was called: {commit_sequence} != {update_messages}"
        )
        assert created_ats == descending, f"commits list newest first but CreatedAt ascends: {created_ats}"
        by_time = updates_listed[::-1]
    # representation: every unicode CommitMessage must come back byte-for-byte identical,
    # not merely present -- no mojibake, truncation, or normalization by the service
    for sent, entry in zip(update_messages, by_time):
        assert entry["CommitMessage"] == sent, (
            f"CommitMessage was not preserved verbatim: {entry['CommitMessage']!r} != {sent!r}"
        )

    # complete the end-to-end lifecycle explicitly: delete the package and confirm the
    # service actually removes it rather than leaving it in a zombie AVAILABLE state
    opensearch.delete_package(PackageID=package_id)
    _wait_package_deleted(opensearch, package_id)


def _short_name(prefix: str, maxlen: int) -> str:
    suffix = uuid.uuid4().hex[:10]
    return f"{prefix}{suffix}"[:maxlen]


def _create_bucket(ctx: Any, s3: Any, bucket: str) -> None:
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3: Any, bucket: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _delete_package(opensearch: Any, package_id: str) -> None:
    """Delete the package; one the body already deleted answers ResourceNotFoundException or
    ValidationException "Package not found."."""
    try:
        opensearch.delete_package(PackageID=package_id)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "ResourceNotFoundException":
            return
        if error["Code"] == "ValidationException" and error.get("Message") == "Package not found.":
            return
        raise


def _wait_package_available(opensearch: Any, package_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )
        details = resp["PackageDetailsList"]
        if details:
            last_status = details[0]["PackageStatus"]
            if last_status == "AVAILABLE":
                return
            if last_status in ("COPY_FAILED", "VALIDATION_FAILED", "DELETE_FAILED"):
                raise AssertionError(f"package {package_id} entered failure status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"package {package_id} did not reach AVAILABLE within {timeout_s}s (last={last_status})")


def _wait_package_deleted(opensearch: Any, package_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )
        details = resp["PackageDetailsList"]
        if not details:
            return
        last_status = details[0]["PackageStatus"]
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"package {package_id} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"package {package_id} was not removed within {timeout_s}s (last status={last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
