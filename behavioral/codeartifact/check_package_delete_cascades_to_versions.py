"""package-delete-cascades-to-versions."""
from __future__ import annotations

import hashlib
import time

from behavioral_harness import tags

CHECK = "package-delete-cascades-to-versions"
GROUP = "state-machine"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeletePackage removes a package and all of its versions atomically: after the
    call, both DescribePackage and ListPackageVersions no longer resolve the package."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-dom-")
    repo = ctx.unique_name("sim2real-behav-repo-")
    package = ctx.unique_name("sim2real-behav-pkg-")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    fmt = "generic"

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_domain(domain=domain)))
    ca.create_repository(
        domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_repository(domain=domain, repository=repo)))

    for version in ("1.0.0", "2.0.0"):
        content = f"payload-{version}".encode()
        ca.publish_package_version(
            domain=domain,
            repository=repo,
            format=fmt,
            namespace=namespace,
            package=package,
            packageVersion=version,
            assetContent=content,
            assetName=f"payload-{version}.bin",
            assetSHA256=hashlib.sha256(content).hexdigest(),
        )
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: ca.delete_package(
                domain=domain, repository=repo, format=fmt, namespace=namespace, package=package
            )
        )
    )

    versions_before = ca.list_package_versions(
        domain=domain, repository=repo, format=fmt, namespace=namespace, package=package
    )["versions"]
    assert {v["version"] for v in versions_before} == {"1.0.0", "2.0.0"}, (
        f"expected versions {{'1.0.0', '2.0.0'}} before delete, got "
        f"{ {v['version'] for v in versions_before} }"
    )

    deleted = ca.delete_package(
        domain=domain, repository=repo, format=fmt, namespace=namespace, package=package
    )
    assert deleted["deletedPackage"]["package"] == package, (
        f"expected deletedPackage.package == {package!r}, got "
        f"{deleted['deletedPackage'].get('package')!r}"
    )

    expected = (
        "ResourceNotFoundException",
        f"Package not found in repository. Package = {{format={fmt}, name={package}}}",
    )
    refusal = _error(
        lambda: ca.describe_package(
            domain=domain, repository=repo, format=fmt, namespace=namespace, package=package
        )
    )
    assert refusal == expected, (
        f"expected DescribePackage on a deleted package to raise {expected!r}, got {refusal!r}"
    )

    refusal = _error(
        lambda: ca.list_package_versions(
            domain=domain, repository=repo, format=fmt, namespace=namespace, package=package
        )
    )
    expected_versions = (
        "ResourceNotFoundException",
        f"The generic package '{package}' with namespace '{namespace}' does not exist in "
        f"repository '{repo}'.",
    )
    assert refusal == expected_versions, (
        f"expected ListPackageVersions on a deleted package to raise {expected_versions!r}, got "
        f"{refusal!r}"
    )

    # A mutation on the dead package id must not resurrect it. On AWS DeletePackage is
    # idempotent — a second delete is a bare 200 with no
    # `deletedPackage` in the body, not a ResourceNotFoundException (unlike DescribePackage
    # and ListPackageVersions above, which do enforce not-found on reads).
    second_delete = ca.delete_package(
        domain=domain, repository=repo, format=fmt, namespace=namespace, package=package
    )
    assert "deletedPackage" not in second_delete, (
        f"expected a second DeletePackage on an already-deleted package to be a no-op with no "
        f"deletedPackage in the response, got {second_delete!r}"
    )
    refusal = _error(
        lambda: ca.describe_package(
            domain=domain, repository=repo, format=fmt, namespace=namespace, package=package
        )
    )
    assert refusal == expected, (
        f"a double-deleted package must not have been resurrected, but DescribePackage returned "
        f"{refusal!r}, expected {expected!r}"
    )


# ===== shared helpers =====
def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    so an accepted call is not reported as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
