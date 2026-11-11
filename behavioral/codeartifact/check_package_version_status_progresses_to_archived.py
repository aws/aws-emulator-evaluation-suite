"""package-version-status-progresses-to-archived."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-version-status-progresses-to-archived"
GROUP = 'package-version-status'
SERVICES = ['codeartifact']


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


def _page(ca, domain, repo, package, **kw):
    """Paginate ListPackageVersions and return (versions, defaultDisplayVersion).

    Paginated because a listing may span pages; the default display version is a per-response
    field, so it is taken from the first page.
    """
    versions, default = [], None
    for i, page in enumerate(ca.get_paginator("list_package_versions").paginate(
            domain=domain, repository=repo, format="generic", namespace="sim2real",
            package=package, **kw)):
        if i == 0:
            default = page.get("defaultDisplayVersion")
        versions.extend(page["versions"])
    return versions, default


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Published -> Unlisted -> Archived relabels 2.0.0 with a stable revision, reads back each status,
    the status filters partition the listing, defaultDisplayVersion falls back from 2.0.0 to 1.0.0, and
    an Archived version still serves its asset."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-status-walk"
    payloads = {"1.0.0": b"status-walk-payload-v1\n", "2.0.0": b"status-walk-payload-v2\n"}
    scope = dict(format="generic", namespace="sim2real", package=package)

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo,
                          tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    revision = {}
    for version, content in payloads.items():
        published = ca.publish_package_version(
            domain=domain, repository=repo, packageVersion=version, assetContent=content,
            assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(), **scope)
        if version == "1.0.0":
            ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))
        assert published["status"] == "Published", (
            f"the publish of {version} reported status {published['status']!r}, expected Published"
        )
        revision[version] = published["versionRevision"]

    _, default = _page(ca, domain, repo, package)
    assert default == "2.0.0", (
        f"with both versions Published the default display version is {default!r}, expected the "
        f"newest '2.0.0'"
    )

    for target in ("Unlisted", "Archived"):
        moved = ca.update_package_versions_status(
            domain=domain, repository=repo, versions=["2.0.0"], targetStatus=target, **scope)
        assert moved["failedVersions"] == {}, (
            f"the move to {target} reported failures {moved['failedVersions']!r}"
        )
        assert moved["successfulVersions"]["2.0.0"]["status"] == target, (
            f"the move to {target} reported "
            f"{moved['successfulVersions']['2.0.0']['status']!r} instead"
        )
        assert moved["successfulVersions"]["2.0.0"]["revision"] == revision["2.0.0"], (
            f"the move to {target} changed the revision to "
            f"{moved['successfulVersions']['2.0.0']['revision']!r}; a status change relabels a "
            f"version, it does not republish it (was {revision['2.0.0']!r})"
        )
        read = ca.describe_package_version(
            domain=domain, repository=repo, packageVersion="2.0.0", **scope)["packageVersion"]
        assert read["status"] == target, (
            f"after moving to {target} a read returned status {read['status']!r}"
        )

        everything, default = _page(ca, domain, repo, package)
        assert sorted((v["version"], v["status"]) for v in everything) == \
            [("1.0.0", "Published"), ("2.0.0", target)], (
            f"the unfiltered listing returned "
            f"{sorted((v['version'], v['status']) for v in everything)!r}; it must stay "
            f"status-agnostic and report 2.0.0 as {target}"
        )
        assert default == "1.0.0", (
            f"with 2.0.0 {target} the default display version is {default!r}; it must fall back "
            f"to the newest still-Published version '1.0.0'"
        )
        selected, _ = _page(ca, domain, repo, package, status=target)
        assert [v["version"] for v in selected] == ["2.0.0"], (
            f"the status={target} filter returned {[v['version'] for v in selected]!r}, "
            f"expected ['2.0.0']"
        )
        published_only, _ = _page(ca, domain, repo, package, status="Published")
        assert [v["version"] for v in published_only] == ["1.0.0"], (
            f"the status=Published filter returned "
            f"{[v['version'] for v in published_only]!r}, expected ['1.0.0']"
        )

    assert ca.get_package_version_asset(
        domain=domain, repository=repo, packageVersion="2.0.0", asset="payload.bin", **scope
    )["asset"].read() == payloads["2.0.0"], (
        "an Archived version must still serve its assets — Archived stops package managers from "
        "downloading it, it does not delete the bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
