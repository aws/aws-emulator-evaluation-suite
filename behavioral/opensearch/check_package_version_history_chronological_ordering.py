"""package-version-history-chronological-ordering."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-version-history-chronological-ordering"
GROUP = "data-plane"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPackageVersionHistory returns package versions in a single, consistent chronological
    order (by CreatedAt) after two UpdatePackage calls, and each entry's CommitMessage lines up
    with the version we created it with.
    """
    ctx.client("s3")
    bucket = _create_bucket(ctx)

    key_v1 = "sim2real/synonyms-v1.txt"
    key_v2 = "sim2real/synonyms-v2.txt"
    key_v3 = "sim2real/synonyms-v3.txt"
    _put_object(ctx, bucket, key_v1, b"danish, croissant, pastry\n")
    _put_object(ctx, bucket, key_v2, b"danish, croissant, pastry\nice cream, gelato\n")
    _put_object(ctx, bucket, key_v3, b"danish, croissant, pastry\nice cream, gelato\nsneaker, tennis shoe\n")

    client = ctx.client("opensearch")
    pkg_name = _pkg_name(ctx)
    created = client.create_package(
        PackageName=pkg_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key_v1},
    )
    pkg_id = created["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _delete_package_if_present(ctx, pkg_id))
    _wait_package_status(ctx, pkg_id, {"AVAILABLE"}, {"COPY_FAILED", "VALIDATION_FAILED"})

    client.update_package(
        PackageID=pkg_id, PackageSource={"S3BucketName": bucket, "S3Key": key_v2}, CommitMessage="v2-two-entries"
    )
    _wait_package_status(ctx, pkg_id, {"AVAILABLE"}, {"COPY_FAILED", "VALIDATION_FAILED"})

    client.update_package(
        PackageID=pkg_id, PackageSource={"S3BucketName": bucket, "S3Key": key_v3}, CommitMessage="v3-three-entries"
    )
    _wait_package_status(ctx, pkg_id, {"AVAILABLE"}, {"COPY_FAILED", "VALIDATION_FAILED"})

    history = client.get_package_version_history(PackageID=pkg_id)["PackageVersionHistoryList"]
    assert len(history) >= 3, f"expected at least 3 version-history entries, got {history!r}"

    timestamps = [entry["CreatedAt"] for entry in history]
    ascending = all(a <= b for a, b in zip(timestamps, timestamps[1:]))
    descending = all(a >= b for a, b in zip(timestamps, timestamps[1:]))
    assert ascending or descending, f"version history is not consistently ordered by CreatedAt: {timestamps!r}"

    by_message = {entry.get("CommitMessage"): entry["CreatedAt"] for entry in history}
    assert "v2-two-entries" in by_message and "v3-three-entries" in by_message, (
        f"expected both update commit messages present in history: {history!r}"
    )
    assert by_message["v2-two-entries"] <= by_message["v3-three-entries"], (
        "v2 update was not recorded chronologically before v3 update"
    )
    if ascending:
        assert history[0]["CreatedAt"] <= by_message["v2-two-entries"] <= by_message["v3-three-entries"]
    else:
        assert history[0]["CreatedAt"] >= by_message["v3-three-entries"] >= by_message["v2-two-entries"]

    # Independent terminal read after delete: a genuinely-deleted PackageID must be both absent from
    # DescribePackages and refused by GetPackageVersionHistory -- confirmed against real AWS to be
    # ValidationException "Package not found.", not the ResourceNotFoundException the API reference
    # documents.
    client.delete_package(PackageID=pkg_id)
    _wait_package_gone(ctx, pkg_id)
    code, msg = _error_code(lambda: client.get_package_version_history(PackageID=pkg_id))
    assert code == "ValidationException", f"expected ValidationException for a deleted PackageID, got {code!r} ({msg!r})"
    assert msg == "Package not found.", f"expected message 'Package not found.' for a deleted PackageID, got {msg!r}"


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_package_if_present(ctx, pkg_id: str) -> None:
    client = ctx.client("opensearch")
    try:
        client.delete_package(PackageID=pkg_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ValidationException"):
            raise


def _wait_package_gone(ctx, pkg_id: str, timeout_s: float = 120.0) -> None:
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            details = client.describe_packages(Filters=[{"Name": "PackageID", "Value": [pkg_id]}])["PackageDetailsList"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if not details:
            return
        last = details[0]["PackageStatus"]
        if last == "DELETE_FAILED":
            raise AssertionError(f"package {pkg_id} entered DELETE_FAILED")
        time.sleep(3)
    raise AssertionError(f"package {pkg_id} was not deleted within {timeout_s}s (last={last!r})")


def _pkg_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-pkg-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:60]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-os-pkg-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "package-version-history-chronological-ordering"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _put_object(ctx, bucket, key, body: bytes):
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=body)


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _wait_package_status(ctx, pkg_id, ok_statuses, terminal_bad_statuses, timeout_s=600.0):
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        details = client.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [pkg_id]}]
        )["PackageDetailsList"][0]
        last = details["PackageStatus"]
        if last in ok_statuses:
            return details
        if last in terminal_bad_statuses:
            raise AssertionError(f"package {pkg_id} reached bad status {last!r}: {details!r}")
        time.sleep(5)
    raise AssertionError(f"package {pkg_id} did not reach {ok_statuses} within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
