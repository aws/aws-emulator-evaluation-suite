"""codeartifact-concurrent-publish-of-one-version-lets-exactly-one-content-win."""
from __future__ import annotations

import concurrent.futures
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "codeartifact-concurrent-publish-of-one-version-lets-exactly-one-content-win"
GROUP = 'publish'
SERVICES = ['codeartifact']


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Six simultaneous publishes of one version: one succeeds, five get ConflictException, and the
    single stored asset is one racer's bytes in full (never a blend) with a matching size and digest.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    namespace = "sim2real"
    package = ctx.unique_name("sim2real-race-")
    # Distinct payloads of distinct LENGTHS, so a blended artifact cannot coincidentally equal
    # one of them, and each carries its racer index in its bytes.
    payloads = [f"sim2real racer {i}".encode() + bytes([i]) * (1024 * (i + 1))
                for i in range(6)]
    digests = [hashlib.sha256(p).hexdigest() for p in payloads]
    assert len({len(p) for p in payloads}) == 6 and len(set(digests)) == 6, (
        f"the fixture failed to build six distinguishable payloads: sizes "
        f"{[len(p) for p in payloads]!r}"
    )

    def _publish(payload: bytes) -> tuple[bool, str | tuple[str, str]]:
        try:
            response = ca.publish_package_version(
                domain=domain, repository=repository, format="generic", namespace=namespace,
                package=package, packageVersion="1.0.0", assetContent=payload,
                assetName="payload.bin", assetSHA256=hashlib.sha256(payload).hexdigest())
            return True, response["status"]
        except ClientError as exc:
            return False, (exc.response["Error"]["Code"], exc.response["Error"]["Message"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(_publish, payloads))

    winners = [outcome for ok, outcome in outcomes if ok]
    losers = [outcome for ok, outcome in outcomes if not ok]
    assert len(winners) == 1, (
        f"expected exactly one of six concurrent publishes of the same version to succeed, got "
        f"{len(winners)}: {outcomes!r}"
    )
    conflict = (f"Cannot update existing generic package version '{namespace}/{package}/1.0.0' "
                "with status 'Published'. Only 'Unfinished' package versions can be updated.")
    for loser in set(losers):
        assert loser == ("ConflictException", conflict), (
            f"the five losing publishes must all fail with ConflictException {conflict!r}, got "
            f"{sorted(set(losers))!r}: {outcomes!r}"
        )

    assets = _paginate(ca.list_package_version_assets, "assets", domain=domain,
                      repository=repository, format="generic", namespace=namespace,
                      package=package, packageVersion="1.0.0")
    assert len(assets) == 1, (
        f"expected exactly one stored asset after six contending publishes, got "
        f"{[(a['name'], a['size']) for a in assets]!r}"
    )
    stored = ca.get_package_version_asset(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=package, packageVersion="1.0.0", asset="payload.bin")["asset"].read()
    assert stored in payloads, (
        f"the stored asset is {len(stored)!r} bytes hashing to "
        f"{hashlib.sha256(stored).hexdigest()!r}, which is none of the six published payloads "
        f"(sizes {[len(p) for p in payloads]!r}, digests {digests!r}) — a blended artifact"
    )
    assert assets[0]["size"] == len(stored), (
        f"ListPackageVersionAssets reports size {assets[0]['size']!r} for {len(stored)!r} stored "
        f"bytes"
    )
    assert assets[0]["hashes"]["SHA-256"] == hashlib.sha256(stored).hexdigest(), (
        f"the recorded digest {assets[0]['hashes']['SHA-256']!r} disagrees with the stored bytes "
        f"({hashlib.sha256(stored).hexdigest()!r})"
    )

    versions = _paginate(ca.list_package_versions, "versions", domain=domain,
                        repository=repository, format="generic", namespace=namespace,
                        package=package)
    assert {v["version"] for v in versions} == {"1.0.0"}, (
        f"the contention created more than the one contended version: "
        f"{[v['version'] for v in versions]!r}"
    )


def _paginate(operation, key: str, **kwargs) -> list[dict]:
    """Every page of a CodeArtifact List* call."""
    out, next_token = [], None
    while True:
        page = operation(**kwargs, **({"nextToken": next_token} if next_token else {}))
        out.extend(page.get(key, []))
        next_token = page.get("nextToken")
        if not next_token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
