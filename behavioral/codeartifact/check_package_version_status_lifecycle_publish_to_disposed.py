"""package-version-status-lifecycle-publish-to-disposed."""
from __future__ import annotations

import hashlib
import time

from behavioral_harness import tags

CHECK = "package-version-status-lifecycle-publish-to-disposed"
GROUP = "state-machine"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A package version moves Published -> Unlisted -> Archived -> Disposed, each status read
    back by DescribePackageVersion; Disposed keeps its metadata, and its asset is still listed
    immediately afterwards because asset removal is asynchronous."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-dom-")
    repo = ctx.unique_name("sim2real-behav-repo-")
    package = ctx.unique_name("sim2real-behav-pkg-")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    version = "1.0.0"
    content = b"sim2real behavioral fidelity payload"
    sha256 = hashlib.sha256(content).hexdigest()
    fmt = "generic"

    ca.create_domain(domain=domain)
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_domain(domain=domain)))
    ca.create_repository(domain=domain, repository=repo)
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_repository(domain=domain, repository=repo)))

    published = ca.publish_package_version(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=version,
        assetContent=content,
        assetName="payload.bin",
        assetSHA256=sha256,
    )
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: ca.delete_package(
                domain=domain, repository=repo, format=fmt, namespace=namespace, package=package
            )
        )
    )
    assert published["status"] == "Published", (
        f"publish_package_version returned status {published['status']!r}, expected 'Published'"
    )

    described = ca.describe_package_version(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=version,
    )["packageVersion"]
    assert described["status"] == "Published", (
        f"describe_package_version reported status {described['status']!r} right after publish, "
        f"expected 'Published'"
    )

    # Published -> Unlisted
    result = ca.update_package_versions_status(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        versions=[version],
        targetStatus="Unlisted",
    )
    assert version in result["successfulVersions"], (
        f"update_package_versions_status(Unlisted) reported successfulVersions="
        f"{result['successfulVersions']!r}, expected {version!r} to be present"
    )
    assert result["successfulVersions"][version]["status"] == "Unlisted", (
        f"update_package_versions_status(Unlisted) reported status "
        f"{result['successfulVersions'][version]['status']!r}, expected 'Unlisted'"
    )
    described = ca.describe_package_version(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=version,
    )["packageVersion"]
    assert described["status"] == "Unlisted", (
        f"describe_package_version reported status {described['status']!r} after the Unlisted "
        f"transition, expected 'Unlisted'"
    )

    # Unlisted -> Archived
    result = ca.update_package_versions_status(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        versions=[version],
        targetStatus="Archived",
    )
    assert version in result["successfulVersions"], (
        f"update_package_versions_status(Archived) reported successfulVersions="
        f"{result['successfulVersions']!r}, expected {version!r} to be present"
    )
    described = ca.describe_package_version(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=version,
    )["packageVersion"]
    assert described["status"] == "Archived", (
        f"describe_package_version reported status {described['status']!r} after the Archived "
        f"transition, expected 'Archived'"
    )

    # Archived -> Disposed: metadata is retained under a terminal status.
    dispose_result = ca.dispose_package_versions(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        versions=[version],
    )
    assert version in dispose_result["successfulVersions"], (
        f"dispose_package_versions reported successfulVersions={dispose_result['successfulVersions']!r}, "
        f"expected {version!r} to be present"
    )
    described = ca.describe_package_version(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=version,
    )["packageVersion"]
    assert described["status"] == "Disposed", (
        f"describe_package_version reported status {described['status']!r} after disposal, "
        f"expected 'Disposed'"
    )
    assert described["version"] == version, (
        f"describe_package_version reported version {described['version']!r} after disposal, "
        f"expected {version!r} — the metadata record must be retained, not replaced"
    )

    # DisposePackageVersions' asset removal is documented as permanent but is NOT synchronous on
    # real AWS: assert the immediately-observable fact instead of a removal this check's budget
    # cannot wait out.
    assets = ca.list_package_version_assets(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=version,
    )["assets"]
    asset_names = [a["name"] for a in assets]
    assert asset_names == ["payload.bin"], (
        f"list_package_version_assets returned assets={asset_names!r} immediately after disposal, "
        f"expected ['payload.bin'] still listed unchanged (asset removal is asynchronous)"
    )

    # The version is permanently retained in the Disposed state (it cannot revert).
    versions_listing = ca.list_package_versions(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        status="Disposed",
    )["versions"]
    assert version in {v["version"] for v in versions_listing}, (
        f"list_package_versions(status='Disposed') returned versions="
        f"{[v['version'] for v in versions_listing]!r}, expected {version!r} to be present"
    )



# ===== shared helpers =====
def _error_code(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "response", {}).get("Error", {}).get("Code")
    return None


def _teardown(fn, timeout_s: float = 30.0) -> None:
    """Run a teardown call: done on success or ResourceNotFoundException, retried while
    ConflictException says a dependent is still being released, and raised otherwise."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
