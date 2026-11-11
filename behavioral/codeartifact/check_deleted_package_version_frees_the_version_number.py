"""deleted-package-version-frees-the-version-number."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-package-version-frees-the-version-number"
GROUP = 'package-version-deletion'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        "the call SUCCEEDED where real AWS rejects it — there is no error code to compare"
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
      "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeletePackageVersions the version leaves every listing, status=Deleted is refused as a
    list filter, and re-publishing 1.0.0 with different bytes succeeds under a new revision.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-delete-reuse"
    first_bytes = b"first-build-of-1.0.0\n"
    second_bytes = b"second-build-of-1.0.0-after-delete\n"
    scope = dict(format="generic", namespace="sim2real", package=package)

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo,
                          tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    published = ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", assetContent=first_bytes,
        assetName="payload.bin", assetSHA256=hashlib.sha256(first_bytes).hexdigest(), **scope)
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))
    first_revision = published["versionRevision"]

    before_delete = _listed(ca, domain, repo, package, status="Published")
    assert [v["version"] for v in before_delete] == ["1.0.0"], (
        f"status=Published as a LIST filter returned {[v['version'] for v in before_delete]!r}, "
        f"expected ['1.0.0'] — this is the positive control proving the status filter itself "
        f"works, so the later ValidationException on status=Deleted means that value specifically "
        f"is refused, not that every status filter is"
    )

    removed = ca.delete_package_versions(
        domain=domain, repository=repo, versions=["1.0.0"], **scope)
    assert removed["failedVersions"] == {}, (
        f"the delete reported failures {removed['failedVersions']!r}"
    )
    assert removed["successfulVersions"]["1.0.0"]["status"] == "Deleted", (
        f"the delete reported {removed['successfulVersions']!r}, expected 1.0.0 Deleted"
    )

    assert _listed(ca, domain, repo, package) == [], (
        f"the deleted version still appears in the default listing: "
        f"{_listed(ca, domain, repo, package)!r}"
    )
    code, message = _error(lambda: _listed(ca, domain, repo, package, status="Deleted"))
    assert code == "ValidationException", (
        f"status=Deleted as a LIST filter returned {code!r}, expected ValidationException — the "
        f"model declares DELETED in PackageVersionStatus but the service refuses it as an input"
    )
    assert message == "Deleted is not a valid input status", (
        f"the filter refusal said {message!r}, expected 'Deleted is not a valid input status'"
    )

    republished = ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", assetContent=second_bytes,
        assetName="payload.bin", assetSHA256=hashlib.sha256(second_bytes).hexdigest(), **scope)
    assert republished["status"] == "Published", (
        f"re-publishing a deleted version number reported {republished['status']!r}, expected "
        f"Published — delete frees the number where dispose does not"
    )
    assert republished["versionRevision"] != first_revision, (
        f"the re-publish reused revision {first_revision!r}; different bytes must mint a new one"
    )
    assert ca.get_package_version_asset(
        domain=domain, repository=repo, packageVersion="1.0.0", asset="payload.bin", **scope
    )["asset"].read() == second_bytes, (
        "the re-published version still serves the deleted build's bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
