"""publish-duplicate-immutable-version-rejected."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "publish-duplicate-immutable-version-rejected"
GROUP = "error-semantics"
SERVICES = ["codeartifact"]


def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected ConflictException, but the call SUCCEEDED and returned {result!r}")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publishing a second asset to an already-Published generic package version is rejected
    with ConflictException, and the original asset is left untouched."""
    ca = ctx.client("codeartifact")
    domain = (ctx.unique_name("sim2real-ca-") + "0").lower()
    repo = ctx.unique_name("sim2real-ca-repo-")
    namespace = "sim2real-ns"
    package = "sim2real-pkg"
    version = "1.0.0"

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    first_content = b"original-asset-bytes"
    first = ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        packageVersion=version,
        assetContent=first_content,
        assetName="asset-one.bin",
        assetSHA256=_sha256(first_content),
    )
    ctx.on_cleanup(
        lambda: ca.delete_package_versions(
            domain=domain,
            repository=repo,
            format="generic",
            namespace=namespace,
            package=package,
            versions=[version],
        )
    )
    assert first["status"] == "Published", f"expected Published, got {first['status']!r}"

    # Second publish adds a *different* asset to the same (now-immutable) version.
    second_content = b"attempted-overwrite-bytes"
    refusal = _error(
        lambda: ca.publish_package_version(
            domain=domain,
            repository=repo,
            format="generic",
            namespace=namespace,
            package=package,
            packageVersion=version,
            assetContent=second_content,
            assetName="asset-two.bin",
            assetSHA256=_sha256(second_content),
        )
    )
    expected = (
        "ConflictException",
        f"Cannot update existing generic package version '{namespace}/{package}/{version}' with "
        f"status 'Published'. Only 'Unfinished' package versions can be updated.",
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Effect absent: the version still contains only the originally published asset.
    assets = ca.list_package_version_assets(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        packageVersion=version,
    )["assets"]
    names = {a["name"] for a in assets}
    assert names == {"asset-one.bin"}, f"expected only asset-one.bin, got {names}"
    original_bytes = ca.get_package_version_asset(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        packageVersion=version,
        asset="asset-one.bin",
    )["asset"].read()
    assert original_bytes == first_content, (
        f"expected the original asset bytes {first_content!r} to remain untouched, got {original_bytes!r}"
    )

    # Positive control: publishing a *different* version succeeds normally.
    other_version = "2.0.0"
    other_content = b"second-version-bytes"
    second_publish = ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        packageVersion=other_version,
        assetContent=other_content,
        assetName="asset-one.bin",
        assetSHA256=_sha256(other_content),
    )
    ctx.on_cleanup(
        lambda: ca.delete_package_versions(
            domain=domain,
            repository=repo,
            format="generic",
            namespace=namespace,
            package=package,
            versions=[other_version],
        )
    )
    assert second_publish["status"] == "Published", (
        f"expected Published, got {second_publish['status']!r}"
    )
    assert second_publish["version"] == other_version, (
        f"expected version {other_version!r}, got {second_publish['version']!r}"
    )

    # Read the bytes back through GetPackageVersionAsset rather than trusting the publish echo.
    served = ca.get_package_version_asset(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        packageVersion=other_version,
        asset="asset-one.bin",
    )["asset"].read()
    assert served == other_content, (
        f"expected the independently-read bytes for {other_version!r} to be {other_content!r}, "
        f"got {served!r}"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
