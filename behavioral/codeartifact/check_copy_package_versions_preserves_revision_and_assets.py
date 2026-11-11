"""copy-package-versions-preserves-revision-and-assets."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-package-versions-preserves-revision-and-assets"
GROUP = 'package-copy'
SERVICES = ['codeartifact']

_ASSETS = {
    "payload.bin": b"\x00\xffcopy-me-byte-for-byte\r\n",
    "sidecar.txt": b"a second asset on the same version\n",
}


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


def _assets(ca, domain, repo, **scope):
    out = []
    for page in ca.get_paginator("list_package_version_assets").paginate(
            domain=domain, repository=repo, **scope):
        out.extend(page["assets"])
    return {a["name"]: a for a in out}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyPackageVersions carries a version to another repository with the source's revision,
    every asset's metadata and digests and identical bytes, and leaves the source version in
    place."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    src = ctx.unique_name("sim2real-behav-ca-src-")
    dst = ctx.unique_name("sim2real-behav-ca-dst-")
    package = "sim2real-copied"
    scope = dict(format="generic", namespace="sim2real", package=package)

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    for repo in (src, dst):
        ca.create_repository(domain=domain, repository=repo,
                              tags=[{"key": "sim2real", "value": CHECK}])
        ctx.on_cleanup(lambda r=repo: ca.delete_repository(domain=domain, repository=r))

    published = None
    for name, content in _ASSETS.items():
        published = ca.publish_package_version(
            domain=domain, repository=src, packageVersion="1.0.0", assetContent=content,
            assetName=name, assetSHA256=hashlib.sha256(content).hexdigest(),
            unfinished=name != "sidecar.txt", **scope)
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=src, **scope))
    source_revision = published["versionRevision"]
    assert published["status"] == "Published", (
        f"the final publish left the version {published['status']!r}, expected Published — the "
        f"first asset went up as unfinished and the last one closes the version"
    )
    source_assets = _assets(ca, domain, src, packageVersion="1.0.0", **scope)
    assert sorted(source_assets) == sorted(_ASSETS), (
        f"the source version holds assets {sorted(source_assets)!r}, expected "
        f"{sorted(_ASSETS)!r}"
    )

    copied = ca.copy_package_versions(
        domain=domain, sourceRepository=src, destinationRepository=dst, format="generic",
        namespace="sim2real", package=package, versions=["1.0.0"])
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=dst, **scope))
    assert copied["failedVersions"] == {}, (
        f"the copy reported failures {copied['failedVersions']!r}"
    )
    assert copied["successfulVersions"]["1.0.0"]["revision"] == source_revision, (
        f"the copy reports revision {copied['successfulVersions']['1.0.0']['revision']!r}, "
        f"expected the source's {source_revision!r} — a copy must not re-mint the revision"
    )

    landed = ca.describe_package_version(
        domain=domain, repository=dst, packageVersion="1.0.0", **scope)["packageVersion"]
    assert landed["revision"] == source_revision, (
        f"the destination reads revision {landed['revision']!r}, expected {source_revision!r}"
    )
    assert landed["origin"]["domainEntryPoint"]["repositoryName"] == src, (
        f"the destination's origin names {landed['origin']['domainEntryPoint']!r}, expected the "
        f"source repository {src!r}"
    )

    dest_assets = _assets(ca, domain, dst, packageVersion="1.0.0", **scope)
    assert dest_assets == source_assets, (
        f"the destination's asset metadata is {dest_assets!r}, expected the source's "
        f"{source_assets!r} — sizes and all four digests must survive the copy"
    )
    for name, content in _ASSETS.items():
        served = ca.get_package_version_asset(
            domain=domain, repository=dst, packageVersion="1.0.0", asset=name, **scope
        )["asset"].read()
        assert served == content, (
            f"the copied asset {name!r} came back as {served!r}, expected {content!r}"
        )

    assert ca.describe_package_version(
        domain=domain, repository=src, packageVersion="1.0.0", **scope
    )["packageVersion"]["revision"] == source_revision, (
        "the copy disturbed the source version"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
