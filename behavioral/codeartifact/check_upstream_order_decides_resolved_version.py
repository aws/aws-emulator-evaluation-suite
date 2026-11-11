"""upstream-order-decides-resolved-version."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upstream-order-decides-resolved-version"
GROUP = 'upstreams'
SERVICES = ['codeartifact']


def _delete_repo(ca, domain, repo, deadline=90.0):
    """DeleteRepository, retrying the upstream-reference conflict.

    A repository still named as an upstream cannot be deleted, and the reference outlives the
    downstream repository's own delete by several seconds (measured), so a single-shot cleanup
    strands both upstreams AND the domain that holds them.
    """
    end = time.time() + deadline
    while True:
        try:
            ca.delete_repository(domain=domain, repository=repo)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


def _delete_domain(ca, domain, deadline=90.0):
    """DeleteDomain, retrying while a repository the cleanup already deleted still counts."""
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


def _publish(ca, domain, repo, package, version, content):
    ca.publish_package_version(
        domain=domain, repository=repo, format="generic", namespace="sim2real",
        package=package, packageVersion=version, assetContent=content,
        assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(),
    )


def _asset_bytes(ca, domain, repo, package, version):
    return ca.get_package_version_asset(
        domain=domain, repository=repo, format="generic", namespace="sim2real",
        package=package, packageVersion=version, asset="payload.bin",
    )["asset"].read()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """With two upstreams holding different builds of the same 1.0.0, the version (bytes, revision and
    origin) resolves from the first upstream in the list; reversing the list resolves it from the other."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    up_a = ctx.unique_name("sim2real-behav-ca-upa-")
    up_b = ctx.unique_name("sim2real-behav-ca-upb-")
    down = ctx.unique_name("sim2real-behav-ca-dn-")
    dest_a = ctx.unique_name("sim2real-behav-ca-ta-")
    dest_b = ctx.unique_name("sim2real-behav-ca-tb-")
    package = "sim2real-shared"

    resource_tags = [{"key": "sim2real", "value": CHECK}]

    ca.create_domain(domain=domain, tags=resource_tags)
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))

    for repo, content in ((up_a, b"bytes-from-upstream-a\n"), (up_b, b"bytes-from-upstream-b\n")):
        ca.create_repository(domain=domain, repository=repo, tags=resource_tags)
        ctx.on_cleanup(lambda r=repo: _delete_repo(ca, domain, r))
        _publish(ca, domain, repo, package, "1.0.0", content)

    rev_a = ca.describe_package_version(
        domain=domain, repository=up_a, format="generic", namespace="sim2real",
        package=package, packageVersion="1.0.0")["packageVersion"]["revision"]
    rev_b = ca.describe_package_version(
        domain=domain, repository=up_b, format="generic", namespace="sim2real",
        package=package, packageVersion="1.0.0")["packageVersion"]["revision"]
    assert rev_a != rev_b, (
        f"the two upstreams must hold DISTINGUISHABLE builds, but both revisions are {rev_a!r}"
    )

    ca.create_repository(domain=domain, repository=down, tags=resource_tags,
                         upstreams=[{"repositoryName": up_a}, {"repositoryName": up_b}])
    ctx.on_cleanup(lambda: _delete_repo(ca, domain, down))
    ctx.on_cleanup(lambda: ca.update_repository(domain=domain, repository=down, upstreams=[]))

    for dest in (dest_a, dest_b):
        ca.create_repository(domain=domain, repository=dest, tags=resource_tags)
        ctx.on_cleanup(lambda d=dest: _delete_repo(ca, domain, d))

    first = ca.copy_package_versions(
        domain=domain, sourceRepository=down, destinationRepository=dest_a, format="generic",
        namespace="sim2real", package=package, versions=["1.0.0"], includeFromUpstream=True)
    assert first["successfulVersions"]["1.0.0"]["revision"] == rev_a, (
        f"with upstreams [a, b] the resolved revision was "
        f"{first['successfulVersions']['1.0.0']['revision']!r}, expected upstream a's {rev_a!r}"
    )
    assert _asset_bytes(ca, domain, dest_a, package, "1.0.0") == b"bytes-from-upstream-a\n", (
        f"the resolved asset bytes were "
        f"{_asset_bytes(ca, domain, dest_a, package, '1.0.0')!r}, expected upstream a's"
    )
    origin_a = ca.describe_package_version(
        domain=domain, repository=dest_a, format="generic", namespace="sim2real",
        package=package, packageVersion="1.0.0")["packageVersion"]["origin"]
    assert origin_a["domainEntryPoint"]["repositoryName"] == up_a, (
        f"origin names {origin_a['domainEntryPoint']!r}, expected the first upstream {up_a!r}"
    )

    ca.update_repository(domain=domain, repository=down,
                         upstreams=[{"repositoryName": up_b}, {"repositoryName": up_a}])
    second = ca.copy_package_versions(
        domain=domain, sourceRepository=down, destinationRepository=dest_b, format="generic",
        namespace="sim2real", package=package, versions=["1.0.0"], includeFromUpstream=True)
    assert second["successfulVersions"]["1.0.0"]["revision"] == rev_b, (
        f"after reversing the upstream list the resolved revision was "
        f"{second['successfulVersions']['1.0.0']['revision']!r}, expected upstream b's {rev_b!r}"
    )
    assert _asset_bytes(ca, domain, dest_b, package, "1.0.0") == b"bytes-from-upstream-b\n", (
        f"after reversing the list the asset bytes were "
        f"{_asset_bytes(ca, domain, dest_b, package, '1.0.0')!r}, expected upstream b's"
    )
    origin_b = ca.describe_package_version(
        domain=domain, repository=dest_b, format="generic", namespace="sim2real",
        package=package, packageVersion="1.0.0")["packageVersion"]["origin"]
    assert origin_b["domainEntryPoint"]["repositoryName"] == up_b, (
        f"after reversing the upstream list, origin names "
        f"{origin_b['domainEntryPoint']!r}, expected the now-first upstream {up_b!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
