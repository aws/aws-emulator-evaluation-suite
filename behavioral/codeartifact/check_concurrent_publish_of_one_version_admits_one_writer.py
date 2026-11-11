"""concurrent-publish-of-one-version-admits-one-writer."""
from __future__ import annotations

import concurrent.futures
import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-publish-of-one-version-admits-one-writer"
GROUP = 'package-publish-concurrency'
SERVICES = ['codeartifact']

_WRITERS = 6


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


def _versions(ca, domain, repo, **scope):
    out = []
    for page in ca.get_paginator("list_package_versions").paginate(
            domain=domain, repository=repo, **scope):
        out.extend(page["versions"])
    return out


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Of six concurrent publishes of distinct payloads to version 1.0.0 exactly one succeeds and
    the rest fail with the exact ConflictException, and the stored revision, asset and SHA-256 are
    the winner's."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-race"
    scope = dict(format="generic", namespace="sim2real", package=package)
    payloads = {i: ("payload-from-writer-%d\n" % i).encode() for i in range(_WRITERS)}

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo,
                          tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))

    def _publish(writer):
        content = payloads[writer]
        try:
            resp = ca.publish_package_version(
                domain=domain, repository=repo, packageVersion="1.0.0", assetContent=content,
                assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(), **scope)
            return writer, "published", resp["versionRevision"]
        except ClientError as exc:
            return writer, exc.response["Error"]["Code"], exc.response["Error"]["Message"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=_WRITERS) as pool:
        outcomes = list(pool.map(_publish, sorted(payloads)))

    winners = [o for o in outcomes if o[1] == "published"]
    losers = [o for o in outcomes if o[1] != "published"]
    assert len(winners) == 1, (
        f"{len(winners)} of {_WRITERS} concurrent publishes of the same version succeeded: "
        f"{outcomes!r}. The version number must be claimed atomically"
    )
    conflict = (f"Cannot update existing generic package version '{scope['namespace']}/{package}/1.0.0' "
                "with status 'Published'. Only 'Unfinished' package versions can be updated.")
    for _, code, message in losers:
        assert (code, message) == ("ConflictException", conflict), (
            f"the losing writers returned {sorted({o[1:] for o in losers})!r}, expected every one to "
            f"be ConflictException {conflict!r}"
        )

    winner, _, revision = winners[0]
    stored = _versions(ca, domain, repo, **scope)
    assert [v["version"] for v in stored] == ["1.0.0"], (
        f"the race left versions {[v['version'] for v in stored]!r}, expected exactly ['1.0.0']"
    )
    assert stored[0]["revision"] == revision, (
        f"the stored revision {stored[0]['revision']!r} is not the winner's {revision!r}"
    )
    served = ca.get_package_version_asset(
        domain=domain, repository=repo, packageVersion="1.0.0", asset="payload.bin", **scope
    )["asset"].read()
    assert served == payloads[winner], (
        f"the stored asset is {served!r}, but writer {winner} won with {payloads[winner]!r} — the "
        f"winner's bytes are the ones that must survive"
    )
    assets = ca.list_package_version_assets(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope)["assets"]
    assert [a["name"] for a in assets] == ["payload.bin"], (
        f"the race left assets {[a['name'] for a in assets]!r}, expected one"
    )
    assert assets[0]["hashes"]["SHA-256"] == hashlib.sha256(payloads[winner]).hexdigest(), (
        f"the stored digest is {assets[0]['hashes']['SHA-256']!r}, expected the winner's "
        f"{hashlib.sha256(payloads[winner]).hexdigest()!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
