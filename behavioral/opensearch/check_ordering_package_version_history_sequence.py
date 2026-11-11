"""ordering-package-version-history-sequence."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ordering-package-version-history-sequence"
GROUP = "ordering"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPackageVersionHistory returns the versions created via CreatePackage and
    successive UpdatePackage calls sorted by CreatedAt, newest or oldest first (no
    direction is documented), with the commits in update order along that direction."""
    s3 = ctx.client("s3")
    aos = ctx.client("opensearch")
    bucket = _create_bucket(ctx, s3)

    key_v1 = "dict-v1.txt"
    s3.put_object(Bucket=bucket, Key=key_v1, Body=b"danish, croissant, pastry\n")

    pkg_name = ctx.unique_name("sim2real-pkg-").lower()
    resp = aos.create_package(
        PackageName=pkg_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key_v1},
    )
    package_id = resp["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: aos.delete_package(PackageID=package_id))
    _wait_package_status(ctx, aos, package_id, "AVAILABLE")

    # Successive updates, each waited out to AVAILABLE before the next fires,
    # pinning a strict update order.
    for n, commit in ((2, "v2"), (3, "v3")):
        key = f"dict-v{n}.txt"
        s3.put_object(Bucket=bucket, Key=key, Body=f"sneaker-{n}, tennis shoe\n".encode())
        aos.update_package(
            PackageID=package_id,
            PackageSource={"S3BucketName": bucket, "S3Key": key},
            CommitMessage=commit,
        )
        _wait_package_status(ctx, aos, package_id, "AVAILABLE")
        _wait_history_length(ctx, aos, package_id, n)

    history = _get_full_history(aos, package_id)
    assert len(history) >= 3, f"expected at least 3 version history entries, got {len(history)}"

    # Versions created inside one timestamp tick share a CreatedAt, so ties are allowed.
    created_ats = [h["CreatedAt"] for h in history]
    # Real AWS lists most-recent-first, but the Smithy docs name no direction, so ascending
    # CreatedAt order passes too; the commit sequence must then follow the same direction.
    assert created_ats == sorted(created_ats, reverse=True) or created_ats == sorted(created_ats), (
        "GetPackageVersionHistory did not return entries sorted by CreatedAt: "
        f"{[h.get('CommitMessage') for h in history]}"
    )

    commit_sequence_most_recent_first = [h.get("CommitMessage") for h in history if h.get("CommitMessage") in ("v2", "v3")]
    assert commit_sequence_most_recent_first == ["v3", "v2"] or (
        commit_sequence_most_recent_first == ["v2", "v3"] and created_ats == sorted(created_ats)
    ), (
        f"most-recent-first commit sequence does not match update order: {commit_sequence_most_recent_first}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _create_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-opensearch-pkg-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_package_status(ctx, aos, package_id: str, want: str) -> None:
    def _status() -> str:
        resp = aos.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )
        return resp["PackageDetailsList"][0]["PackageStatus"]

    terminal = {want, "COPY_FAILED", "VALIDATION_FAILED"}
    status = _poll_until(_status, lambda s: s in terminal, timeout_s=120, interval_s=3)
    assert status == want, f"package entered {status}, not {want}"


def _wait_history_length(ctx, aos, package_id: str, expected_len: int) -> None:
    def _len() -> int:
        return len(_get_full_history(aos, package_id))

    _poll_until(_len, lambda n: n >= expected_len, timeout_s=60, interval_s=2)


def _get_full_history(aos, package_id: str) -> list:
    history: list = []
    next_token = None
    while True:
        kwargs = {"PackageID": package_id}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = aos.get_package_version_history(**kwargs)
        history.extend(resp.get("PackageVersionHistoryList", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return history


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
