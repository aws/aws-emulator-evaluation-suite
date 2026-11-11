"""update-package-creates-new-version-visible-in-history."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-package-creates-new-version-visible-in-history"
GROUP = 'packages'
SERVICES = ['es']


def _wait_available(es, package_id: str, *, budget_s: float = 120.0, poll_s: float = 3.0) -> dict:
    """Poll DescribePackages until ``package_id`` leaves COPYING."""
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = es.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"][0]
        if last["PackageStatus"] != "COPYING":
            return last
        time.sleep(poll_s)
    raise AssertionError(f"package {package_id} still COPYING after {budget_s}s: {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePackage replaces a package's S3 source with a second version, and
    GetPackageVersionHistory then lists both versions, newest first.
    """
    s3 = ctx.client("s3")
    es = ctx.client("es")
    bucket = ctx.unique_name("sim2real-behav-es-upkg-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_object(Bucket=bucket, Key="v1.txt", Body=b"a,b\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="v1.txt"))
    s3.put_object(Bucket=bucket, Key="v2.txt", Body=b"a,b\nc,d\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="v2.txt"))

    package_name = ctx.unique_name("sim2realbehavupkg")[:28]
    pkg = es.create_package(
        PackageName=package_name, PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": "v1.txt"},
    )["PackageDetails"]
    pkg_id = pkg["PackageID"]
    ctx.on_cleanup(lambda: es.delete_package(PackageID=pkg_id))

    before = _wait_available(es, pkg_id)
    assert before["PackageStatus"] == "AVAILABLE", (
        f"package should reach AVAILABLE before update, got {before['PackageStatus']!r}"
    )

    history_before = es.get_package_version_history(PackageID=pkg_id)["PackageVersionHistoryList"]
    versions_before = [v["PackageVersion"] for v in history_before]
    assert versions_before == ["v1"], (
        f"a never-updated AVAILABLE package should list only its initial version 'v1', "
        f"got {versions_before!r}"
    )

    es.update_package(PackageID=pkg_id, PackageSource={"S3BucketName": bucket, "S3Key": "v2.txt"})
    after = _wait_available(es, pkg_id)
    assert after["PackageStatus"] == "AVAILABLE", (
        f"package should return to AVAILABLE after update, got {after['PackageStatus']!r}"
    )

    history = es.get_package_version_history(PackageID=pkg_id)["PackageVersionHistoryList"]
    versions = [v["PackageVersion"] for v in history]
    assert versions == ["v2", "v1"], (
        f"expected exactly two versions newest-first ['v2', 'v1'], got {versions!r}"
    )
    assert history[0]["CreatedAt"] > history[1]["CreatedAt"], (
        f"v2's CreatedAt should be after v1's, got {history[0]['CreatedAt']!r} vs "
        f"{history[1]['CreatedAt']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
