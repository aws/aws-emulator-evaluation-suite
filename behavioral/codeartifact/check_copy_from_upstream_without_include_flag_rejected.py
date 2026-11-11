"""copy-from-upstream-without-include-flag-rejected."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-from-upstream-without-include-flag-rejected"
GROUP = 'upstreams-rejected'
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


def _delete_repo(ca, domain, repo, deadline=90.0):
    """DeleteRepository, retrying the upstream-reference conflict, which outlives the downstream
    repository's own delete by several seconds."""
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
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyPackageVersions from a repository whose version lives only upstream is refused with
    ResourceNotFoundException and lands nothing; the same call with includeFromUpstream=True copies.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    upstream = ctx.unique_name("sim2real-behav-ca-up-")
    down = ctx.unique_name("sim2real-behav-ca-dn-")
    dest = ctx.unique_name("sim2real-behav-ca-tgt-")
    package = "sim2real-upstream-only"
    content = b"bytes-that-live-only-upstream\n"

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))

    ca.create_repository(domain=domain, repository=upstream,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repo(ca, domain, upstream))
    ca.publish_package_version(
        domain=domain, repository=upstream, format="generic", namespace="sim2real",
        package=package, packageVersion="1.0.0", assetContent=content,
        assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(),
    )

    ca.create_repository(domain=domain, repository=down,
                         upstreams=[{"repositoryName": upstream}],
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repo(ca, domain, down))
    ctx.on_cleanup(lambda: ca.update_repository(domain=domain, repository=down, upstreams=[]))

    ca.create_repository(domain=domain, repository=dest,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repo(ca, domain, dest))

    refusal = _error(lambda: ca.copy_package_versions(
        domain=domain, sourceRepository=down, destinationRepository=dest, format="generic",
        namespace="sim2real", package=package, versions=["1.0.0"]))
    expected = ("ResourceNotFoundException",
                f"The generic package '{package}' with namespace 'sim2real' does not exist in "
                f"repository '{down}'.")
    assert refusal == expected, (
        f"a copy from the downstream without includeFromUpstream returned {refusal!r}, "
        f"expected {expected!r}"
    )

    landed = []
    for page in ca.get_paginator("list_packages").paginate(domain=domain, repository=dest):
        landed.extend(page["packages"])
    assert landed == [], (
        f"the refused copy still landed packages in the destination: {landed!r} — "
        f"a rejection must leave no effect"
    )

    ok = ca.copy_package_versions(
        domain=domain, sourceRepository=down, destinationRepository=dest, format="generic",
        namespace="sim2real", package=package, versions=["1.0.0"], includeFromUpstream=True)
    assert ok["successfulVersions"]["1.0.0"]["status"] == "Published", (
        f"the positive control (same call, includeFromUpstream=True) reported "
        f"{ok['successfulVersions']!r} / {ok['failedVersions']!r}, expected 1.0.0 Published"
    )
    assert ca.get_package_version_asset(
        domain=domain, repository=dest, format="generic", namespace="sim2real",
        package=package, packageVersion="1.0.0", asset="payload.bin",
    )["asset"].read() == content, "the control copy did not carry the upstream's asset bytes"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
