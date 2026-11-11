"""get-package-version-asset-after-disposal-blocked."""
from __future__ import annotations

import hashlib
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "get-package-version-asset-after-disposal-blocked"
GROUP = "overly-permissive"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """For at least 10 s after DisposePackageVersions records a version as Disposed,
    GetPackageVersionAsset keeps serving its original bytes, and a never-disposed sibling
    version stays downloadable, so the read path itself is healthy."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(
        domain=domain, repository=repository, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    package = ctx.unique_name("disposable-pkg-")
    asset_name = f"{package}-1.0.0.tar.gz"
    content = b"payload-that-will-be-disposed"
    ca.publish_package_version(
        domain=domain,
        repository=repository,
        format="generic",
        namespace="sim2real",
        package=package,
        packageVersion="1.0.0",
        assetContent=content,
        assetName=asset_name,
        assetSHA256=hashlib.sha256(content).hexdigest(),
    )

    # Baseline: the asset is retrievable before disposal.
    before = ca.get_package_version_asset(
        domain=domain,
        repository=repository,
        format="generic",
        namespace="sim2real",
        package=package,
        packageVersion="1.0.0",
        asset=asset_name,
    )
    got_before = before["asset"].read()
    assert got_before == content, f"pre-disposal read returned {got_before!r}, expected {content!r}"

    dispose_resp = ca.dispose_package_versions(
        domain=domain,
        repository=repository,
        format="generic",
        namespace="sim2real",
        package=package,
        versions=["1.0.0"],
    )
    assert "1.0.0" in dispose_resp["successfulVersions"], (
        f"dispose_package_versions did not report 1.0.0 as successful: "
        f"successfulVersions={dispose_resp['successfulVersions']!r}, "
        f"failedVersions={dispose_resp['failedVersions']!r}"
    )

    # Disposal is synchronously reflected in the version's status -- this part
    # IS immediately observable and is a real, asserted state-machine effect.
    status = _poll_until_condition(
        lambda: ca.describe_package_version(
            domain=domain,
            repository=repository,
            format="generic",
            namespace="sim2real",
            package=package,
            packageVersion="1.0.0",
        )["packageVersion"]["status"],
        lambda s: s == "Disposed",
        timeout_s=60,
    )
    assert status == "Disposed", f"status={status!r}"

    # Asset removal is not observed within 10 s of Disposed: every read across that window
    # must still return the ORIGINAL bytes unmodified.
    started = time.monotonic()
    while True:
        still_disposed = ca.get_package_version_asset(
            domain=domain,
            repository=repository,
            format="generic",
            namespace="sim2real",
            package=package,
            packageVersion="1.0.0",
            asset=asset_name,
        )
        got = still_disposed["asset"].read()
        assert got == content, (
            f"disposed asset bytes changed {time.monotonic() - started:.0f}s after disposal: "
            f"got {got!r}, expected {content!r}"
        )
        if time.monotonic() - started >= 10.0:
            break
        time.sleep(2.0)

    # Positive control: a sibling version of the SAME package that was never
    # disposed is still retrievable, proving the mechanism generally works.
    other_asset_name = f"{package}-2.0.0.tar.gz"
    other_content = b"payload-that-survives"
    ca.publish_package_version(
        domain=domain,
        repository=repository,
        format="generic",
        namespace="sim2real",
        package=package,
        packageVersion="2.0.0",
        assetContent=other_content,
        assetName=other_asset_name,
        assetSHA256=hashlib.sha256(other_content).hexdigest(),
    )
    still_good = ca.get_package_version_asset(
        domain=domain,
        repository=repository,
        format="generic",
        namespace="sim2real",
        package=package,
        packageVersion="2.0.0",
        asset=other_asset_name,
    )
    got_still_good = still_good["asset"].read()
    assert got_still_good == other_content, (
        f"undisposed sibling version 2.0.0 read {got_still_good!r}, expected {other_content!r}"
    )


# ===== shared helpers =====
def _poll_until_condition(
    fn: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float = 2.0
) -> Any:
    """Bounded retry: keep calling fn() until predicate(result) is true, or time out."""
    deadline = time.monotonic() + timeout_s
    result = fn()
    while time.monotonic() < deadline:
        result = fn()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

