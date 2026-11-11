"""publish-to-read-only-upstream-repository-blocked."""
from __future__ import annotations

import hashlib
import time
from typing import Any

from behavioral_harness import tags

CHECK = "publish-to-read-only-upstream-repository-blocked"
GROUP = "overly-permissive"
SERVICES = ["codeartifact"]

_NAMESPACE = "sim2real"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A package with origin controls publish: BLOCK / upstream: ALLOW rejects a direct
    PublishPackageVersion while an unrestricted sibling package still publishes; restoring
    publish: ALLOW makes the identical, previously rejected call succeed."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")
    tags_kw = [{"key": "sim2real", "value": CHECK}]

    ca.create_domain(domain=domain, tags=tags_kw)
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repository, tags=tags_kw)
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    # Configure the repository with an external connection, framing it as a mirror
    # that is meant to receive versions from upstream rather than direct publishes.
    ca.associate_external_connection(
        domain=domain, repository=repository, externalConnection="public:npmjs"
    )
    ctx.on_cleanup(
        lambda: ca.disassociate_external_connection(
            domain=domain, repository=repository, externalConnection="public:npmjs"
        )
    )

    mirrored_package = ctx.unique_name("mirrored-pkg-")
    _publish_generic(ca, domain, repository, mirrored_package, "1.0.0")

    # Administrator locks this package down: no more direct publishes allowed, only
    # versions retained from upstream are acceptable from now on.
    ca.put_package_origin_configuration(
        domain=domain,
        repository=repository,
        format="generic",
        namespace=_NAMESPACE,
        package=mirrored_package,
        restrictions={"publish": "BLOCK", "upstream": "ALLOW"},
    )
    restrictions = _poll_until(
        lambda: ca.describe_package(
            domain=domain, repository=repository, format="generic",
            namespace=_NAMESPACE, package=mirrored_package,
        )["package"].get("originConfiguration", {}).get("restrictions", {}),
        lambda r: r.get("publish") == "BLOCK",
        timeout_s=45.0,
    )
    assert restrictions.get("publish") == "BLOCK", (
        f"expected the publish restriction to become BLOCK within 45s, last saw {restrictions!r}"
    )

    refusal = _rejection(
        lambda: _publish_generic(ca, domain, repository, mirrored_package, "1.1.0")
    )
    expected = (
        "ValidationException",
        "This package is configured to block new versions from being published.",
    )
    assert refusal == expected, (
        f"expected {expected!r} for a publish blocked by the origin configuration, got {refusal!r}"
    )

    # Effect absent: the blocked version was never created.
    versions = _versions(ca, domain, repository, mirrored_package)
    assert "1.1.0" not in versions, (
        f"the blocked version 1.1.0 exists in {sorted(versions)!r} after a rejected publish"
    )

    # Positive control: an unrelated package in the SAME repository, with no origin
    # restriction, publishes successfully — proved by an independent read, not the
    # publish call's own response.
    free_package = ctx.unique_name("free-pkg-")
    _publish_generic(ca, domain, repository, free_package, "1.0.0")
    free_versions = _versions(ca, domain, repository, free_package)
    assert "1.0.0" in free_versions, (
        f"the unrestricted sibling's published version is not visible in an independent "
        f"ListPackageVersions read: {sorted(free_versions)!r}"
    )

    # Restore: flipping the switch back to publish: ALLOW makes the identical,
    # previously-rejected call succeed, and the version becomes visible.
    ca.put_package_origin_configuration(
        domain=domain,
        repository=repository,
        format="generic",
        namespace=_NAMESPACE,
        package=mirrored_package,
        restrictions={"publish": "ALLOW", "upstream": "ALLOW"},
    )
    restored = _poll_until(
        lambda: ca.describe_package(
            domain=domain, repository=repository, format="generic",
            namespace=_NAMESPACE, package=mirrored_package,
        )["package"].get("originConfiguration", {}).get("restrictions", {}),
        lambda r: r.get("publish") == "ALLOW",
        timeout_s=45.0,
    )
    assert restored.get("publish") == "ALLOW", (
        f"expected the publish restriction to return to ALLOW within 45s, last saw {restored!r}"
    )
    landed = _publish_generic(ca, domain, repository, mirrored_package, "1.1.0")
    assert landed["status"] == "Published", (
        f"the identical publish after restoring publish: ALLOW reported {landed['status']!r}, "
        f"expected Published"
    )
    restored_versions = _versions(ca, domain, repository, mirrored_package)
    assert "1.1.0" in restored_versions, (
        f"1.1.0 is not visible in an independent ListPackageVersions read after the restored "
        f"publish succeeded: {sorted(restored_versions)!r}"
    )


def _publish_generic(ca, domain: str, repository: str, package: str, version: str) -> dict[str, Any]:
    content = f"asset-content-for-{package}-{version}".encode()
    sha256 = hashlib.sha256(content).hexdigest()
    return ca.publish_package_version(
        domain=domain,
        repository=repository,
        format="generic",
        namespace=_NAMESPACE,
        package=package,
        packageVersion=version,
        assetContent=content,
        assetName=f"{package}-{version}.tar.gz",
        assetSHA256=sha256,
    )


def _versions(ca, domain: str, repository: str, package: str) -> set[str]:
    out: set[str] = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = ca.list_package_versions(
            domain=domain, repository=repository, format="generic",
            namespace=_NAMESPACE, package=package, **kwargs,
        )
        out.update(v["version"] for v in page["versions"])
        next_token = page.get("nextToken")
        if not next_token:
            return out


def _rejection(fn) -> tuple[str, str]:
    """The (code, message) of a call that MUST be rejected; raises if it succeeds."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        error = response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"the call was expected to be rejected but returned {result!r}")


def _poll_until(read, predicate, *, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        observed = read()
        if predicate(observed) or time.monotonic() >= deadline:
            return observed
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
