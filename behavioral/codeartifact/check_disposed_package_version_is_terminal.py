"""disposed-package-version-is-terminal."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disposed-package-version-is-terminal"
GROUP = 'package-version-status'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"the call SUCCEEDED where real AWS rejects it and returned {result!r}"
    )


def _delete_domain(ca, domain, deadline=90.0):
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


def _listed(ca, domain, repo, package, **kw):
    out = []
    for page in ca.get_paginator("list_package_versions").paginate(
            domain=domain, repository=repo, format="generic", namespace="sim2real",
            package=package, **kw):
        out.extend(page["versions"])
    return out


@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """Disposed is terminal: the record stays listed, leaving it is refused, and re-publish conflicts.
    A sibling version takes the same status transition as a positive control.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-disposal"
    content = b"disposal-payload\n"
    scope = dict(format="generic", namespace="sim2real", package=package)

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    published = ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", assetContent=content,
        assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(), **scope)
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))
    revision = published["versionRevision"]

    disposed = ca.dispose_package_versions(
        domain=domain, repository=repo, versions=["1.0.0"], **scope)
    assert disposed["failedVersions"] == {}, (
        f"the disposal reported failures {disposed['failedVersions']!r}"
    )
    assert disposed["successfulVersions"]["1.0.0"]["status"] == "Disposed", (
        f"the disposal reported {disposed['successfulVersions']!r}, expected 1.0.0 Disposed"
    )

    record = ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope)["packageVersion"]
    assert record["status"] == "Disposed", (
        f"after disposal the version reads status {record['status']!r}, expected Disposed"
    )
    assert record["revision"] == revision, (
        f"disposal changed the revision to {record['revision']!r}, expected the published "
        f"{revision!r} — the record is retained, not replaced"
    )
    retained = _listed(ca, domain, repo, package, status="Disposed")
    assert [v["version"] for v in retained] == ["1.0.0"], (
        f"the status=Disposed listing returned {[v['version'] for v in retained]!r}, expected "
        f"['1.0.0'] — a disposed version is retained where a deleted one is not"
    )

    control_version = "1.0.1"
    ca.publish_package_version(
        domain=domain, repository=repo, packageVersion=control_version, assetContent=content,
        assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(), **scope)
    control = ca.update_package_versions_status(
        domain=domain, repository=repo, versions=[control_version], targetStatus="Unlisted", **scope)
    assert control["successfulVersions"][control_version]["status"] == "Unlisted", (
        f"the positive control's transition reported {control['successfulVersions']!r}, expected "
        f"{control_version!r} Unlisted — UpdatePackageVersionsStatus is not universally rejecting, "
        f"so the Disposed refusal below is specific to Disposed rather than to the operation itself"
    )

    stuck = ca.update_package_versions_status(
        domain=domain, repository=repo, versions=["1.0.0"], targetStatus="Unlisted", **scope)
    assert stuck["successfulVersions"] == {}, (
        f"a move out of Disposed reported successes {stuck['successfulVersions']!r}; Disposed is "
        f"absorbing"
    )
    assert stuck["failedVersions"]["1.0.0"]["errorCode"] == "NOT_ALLOWED", (
        f"the refusal's errorCode was {stuck['failedVersions']['1.0.0']['errorCode']!r}, "
        f"expected NOT_ALLOWED"
    )
    assert ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope
    )["packageVersion"]["status"] == "Disposed", (
        "the refused transition still moved the version out of Disposed"
    )

    refusal = _error(lambda: ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", assetContent=content,
        assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(), **scope))
    expected = (
        "ConflictException",
        f"Cannot update existing generic package version 'sim2real/{package}/1.0.0' with status "
        f"'Disposed'. Only 'Unfinished' package versions can be updated.",
    )
    assert refusal == expected, (
        f"re-publishing over a Disposed version returned {refusal!r}, expected {expected!r}"
    )
    assert ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope
    )["packageVersion"]["status"] == "Disposed", (
        "the refused re-publish resurrected the version out of Disposed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
