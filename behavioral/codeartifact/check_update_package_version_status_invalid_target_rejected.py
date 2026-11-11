"""update-package-version-status-invalid-target-rejected."""
from __future__ import annotations

import hashlib
import time

from behavioral_harness import tags

CHECK = "update-package-version-status-invalid-target-rejected"
GROUP = "state-machine"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePackageVersionsStatus refuses Disposed -> Archived with NOT_ALLOWED and SKIPS a valid
    Published -> Archived sibling in the same call, leaving it Published; the sibling's identical
    transition alone succeeds, so its batch-mate blocked it."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-dom-")
    repo = ctx.unique_name("sim2real-behav-repo-")
    package = ctx.unique_name("sim2real-behav-pkg-")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    fmt = "generic"
    resource_tags = [{"key": "sim2real", "value": CHECK}]

    ca.create_domain(domain=domain, tags=resource_tags)
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_domain(domain=domain)))
    ca.create_repository(domain=domain, repository=repo, tags=resource_tags)
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_repository(domain=domain, repository=repo)))

    disposed_version = "1.0.0"
    control_version = "2.0.0"
    for version in (disposed_version, control_version):
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

    ca.dispose_package_versions(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        versions=[disposed_version],
    )
    described = ca.describe_package_version(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=disposed_version,
    )["packageVersion"]
    assert described["status"] == "Disposed", (
        f"DisposePackageVersions left {disposed_version} at status "
        f"{described['status']!r}, expected Disposed"
    )

    # Break exactly one thing, in a batch call that also carries a legitimate sibling
    # transition to the SAME target status: Disposed -> Archived must be refused, and
    # real AWS measured here does NOT grade the sibling independently — it is SKIPPED,
    # not applied, purely because it shares the call with the forbidden version.
    result = ca.update_package_versions_status(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        versions=[disposed_version, control_version],
        targetStatus="Archived",
    )
    assert disposed_version not in result.get("successfulVersions", {}), (
        f"a Disposed version was reported as a success: "
        f"{result.get('successfulVersions', {}).get(disposed_version)!r}"
    )
    assert result["failedVersions"][disposed_version]["errorCode"] == "NOT_ALLOWED", (
        f"disposed_version's failure was {result['failedVersions'][disposed_version]!r}, "
        f"expected errorCode NOT_ALLOWED"
    )
    assert control_version not in result.get("successfulVersions", {}), (
        f"the sibling version, batched with a forbidden transition, was reported as a "
        f"success: {result.get('successfulVersions', {}).get(control_version)!r} — "
        f"expected it to be SKIPPED, not applied"
    )
    assert result["failedVersions"][control_version]["errorCode"] == "SKIPPED", (
        f"the sibling version's failure was {result['failedVersions'][control_version]!r}, "
        f"expected errorCode SKIPPED"
    )

    # Effect absent for both: neither version moved, including the otherwise-valid one.
    described = ca.describe_package_version(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=disposed_version,
    )["packageVersion"]
    assert described["status"] == "Disposed", (
        f"the refused transition left {disposed_version} at status "
        f"{described['status']!r}, expected it to still be Disposed"
    )
    described = ca.describe_package_version(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=control_version,
    )["packageVersion"]
    assert described["status"] == "Published", (
        f"the skipped sibling moved to status {described['status']!r}, expected it to "
        f"stay Published — SKIPPED must have no effect just like NOT_ALLOWED"
    )

    # Positive control: the IDENTICAL transition, alone, is not itself forbidden — it
    # was the batch-mate that blocked it, not anything about the sibling's own state.
    control_result = ca.update_package_versions_status(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        versions=[control_version],
        targetStatus="Archived",
    )
    assert control_version in control_result["successfulVersions"], (
        f"the standalone control call did not succeed: "
        f"{control_result.get('failedVersions', {}).get(control_version)!r}"
    )
    assert control_result["successfulVersions"][control_version]["status"] == "Archived", (
        f"the standalone control's success entry was "
        f"{control_result['successfulVersions'][control_version]!r}, expected Archived"
    )

    # Terminal, independent read: the control's success, once alone, is durable.
    described = ca.describe_package_version(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=control_version,
    )["packageVersion"]
    assert described["status"] == "Archived", (
        f"the control version reads back status {described['status']!r}, expected Archived"
    )


# ===== shared helpers =====
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
