"""package-origin-configuration-blocks-direct-publish."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-origin-configuration-blocks-direct-publish"
GROUP = "server-side"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With publish=BLOCK a PublishPackageVersion is refused with ValidationException and the version
    never lands; restoring ALLOW lets the identical publish succeed as Published, and an unrestricted
    sibling package publishes throughout."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-capubblock-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    repo = ctx.unique_name("repo-")
    ca.create_repository(
        domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    namespace = "sim2real-ns"
    blocked_pkg = ctx.unique_name("blocked-pkg-")
    allowed_pkg = ctx.unique_name("allowed-pkg-")

    v1_content = b"generic-asset-v1"
    v1_sha = hashlib.sha256(v1_content).hexdigest()

    # Publish an initial version so the package exists, then block direct publish.
    ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=blocked_pkg,
        packageVersion="1.0.0",
        assetContent=v1_content,
        assetName="asset.bin",
        assetSHA256=v1_sha,
    )
    ca.put_package_origin_configuration(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=blocked_pkg,
        restrictions={"publish": "BLOCK", "upstream": "ALLOW"},
    )
    _poll_for_publish_restriction(ca, domain, repo, namespace, blocked_pkg, "BLOCK", timeout_s=45.0)

    v2_content = b"generic-asset-v2"
    v2_sha = hashlib.sha256(v2_content).hexdigest()
    refusal = _rejection(
        lambda: ca.publish_package_version(
            domain=domain,
            repository=repo,
            format="generic",
            namespace=namespace,
            package=blocked_pkg,
            packageVersion="2.0.0",
            assetContent=v2_content,
            assetName="asset.bin",
            assetSHA256=v2_sha,
        )
    )
    # AWS CodeArtifact rejects a direct publish blocked by
    # PutPackageOriginConfiguration(publish=BLOCK) with ValidationException (not
    # ConflictException as the origin-controls narrative doc might suggest), and the
    # reason text names the publish origin restriction as the cause.
    expected = (
        "ValidationException",
        "This package is configured to block new versions from being published.",
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Effect absent: the rejected version 2.0.0 must not exist in the package.
    versions = [
        v["version"]
        for v in ca.list_package_versions(
            domain=domain, repository=repo, format="generic", namespace=namespace, package=blocked_pkg
        )["versions"]
    ]
    assert versions == ["1.0.0"], f"unexpected versions after blocked publish: {versions}"

    # Restore leg: lifting the restriction back to ALLOW makes the identical publish
    # call succeed, proving the BLOCK restriction -- and not some other environmental
    # factor -- was what rejected it.
    ca.put_package_origin_configuration(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=blocked_pkg,
        restrictions={"publish": "ALLOW", "upstream": "ALLOW"},
    )
    _poll_for_publish_restriction(ca, domain, repo, namespace, blocked_pkg, "ALLOW", timeout_s=45.0)
    restored = ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=blocked_pkg,
        packageVersion="2.0.0",
        assetContent=v2_content,
        assetName="asset.bin",
        assetSHA256=v2_sha,
    )
    assert (restored["version"], restored["status"]) == ("2.0.0", "Published"), (
        f"expected the restored publish to land as 2.0.0/Published, got "
        f"{restored['version']!r}/{restored['status']!r}"
    )
    restored_versions = [
        v["version"]
        for v in ca.list_package_versions(
            domain=domain, repository=repo, format="generic", namespace=namespace, package=blocked_pkg
        )["versions"]
    ]
    assert sorted(restored_versions) == ["1.0.0", "2.0.0"], (
        f"expected both versions present after the restriction was lifted, got {restored_versions}"
    )

    # Positive control: an unrestricted sibling package publishes fine.
    ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=allowed_pkg,
        packageVersion="1.0.0",
        assetContent=v1_content,
        assetName="asset.bin",
        assetSHA256=v1_sha,
    )
    described = ca.describe_package_version(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=allowed_pkg,
        packageVersion="1.0.0",
    )
    assert described["packageVersion"]["version"] == "1.0.0", (
        f"expected version 1.0.0 for the unrestricted sibling, got "
        f"{described['packageVersion']['version']!r}"
    )
    assert described["packageVersion"]["status"] == "Published", (
        f"expected the unrestricted sibling's publish to land as Published, got "
        f"{described['packageVersion']['status']!r}"
    )


def _rejection(fn):
    """The (code, message) of a call that MUST be rejected; raises if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be rejected but returned {result!r}")


def _poll_for_publish_restriction(
    ca, domain, repo, namespace, package, expected, timeout_s=45.0, interval_s=3.0
):
    import time

    deadline = time.monotonic() + timeout_s
    restrictions = None
    while time.monotonic() < deadline:
        described = ca.describe_package(
            domain=domain, repository=repo, format="generic", namespace=namespace, package=package
        )["package"]
        restrictions = described.get("originConfiguration", {}).get("restrictions", {})
        if restrictions.get("publish") == expected:
            return restrictions
        time.sleep(interval_s)
    raise AssertionError(f"publish restriction never became {expected!r}: {restrictions}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
