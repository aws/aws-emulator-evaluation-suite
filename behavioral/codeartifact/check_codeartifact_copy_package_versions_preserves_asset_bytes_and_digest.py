"""codeartifact-copy-package-versions-preserves-asset-bytes-and-digest."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "codeartifact-copy-package-versions-preserves-asset-bytes-and-digest"
GROUP = 'package-lifecycle'
SERVICES = ['codeartifact']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """CopyPackageVersions duplicates the stored content, not just the version metadata: the copied
    asset's bytes, size and SHA-256 match the source, its origin names the source, and the source
    is left intact.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    source = ctx.unique_name("sim2real-src-")
    destination = ctx.unique_name("sim2real-dst-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=source,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=source))
    ca.create_repository(domain=domain, repository=destination,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=destination))

    namespace = "sim2real"
    package = ctx.unique_name("sim2real-copy-")
    # 256 KiB, deterministic and non-uniform: a truncated or re-encoded copy cannot match it.
    payload = bytes((i * 37 + 11) % 251 for i in range(262144))
    digest = hashlib.sha256(payload).hexdigest()
    ca.publish_package_version(
        domain=domain, repository=source, format="generic", namespace=namespace, package=package,
        packageVersion="1.0.0", assetContent=payload, assetName="payload.bin",
        assetSHA256=digest)

    src_bytes = _asset(ca, domain, source, namespace, package)
    assert src_bytes == payload, (
        f"the source repository stored {len(src_bytes)!r} bytes for a {len(payload)!r}-byte "
        f"publish, so the copy has nothing correct to copy from"
    )

    result = ca.copy_package_versions(
        domain=domain, sourceRepository=source, destinationRepository=destination,
        format="generic", namespace=namespace, package=package, versions=["1.0.0"])
    assert set(result["successfulVersions"]) == {"1.0.0"}, (
        f"CopyPackageVersions reported successful {result['successfulVersions']!r} / failed "
        f"{result.get('failedVersions')!r}"
    )

    dst_bytes = _asset(ca, domain, destination, namespace, package)
    assert dst_bytes == payload, (
        f"the copied asset is {len(dst_bytes)!r} bytes hashing to "
        f"{hashlib.sha256(dst_bytes).hexdigest()!r}, the source published {len(payload)!r} bytes "
        f"hashing to {digest!r}"
    )

    src_assets = _paginate(ca.list_package_version_assets, "assets", domain=domain,
                          repository=source, format="generic", namespace=namespace,
                          package=package, packageVersion="1.0.0")
    dst_assets = _paginate(ca.list_package_version_assets, "assets", domain=domain,
                          repository=destination, format="generic", namespace=namespace,
                          package=package, packageVersion="1.0.0")
    assert [(a["name"], a["size"], a["hashes"]["SHA-256"]) for a in dst_assets] == \
           [(a["name"], a["size"], a["hashes"]["SHA-256"]) for a in src_assets], (
        f"the copy changed the asset identity: destination {dst_assets!r} vs source {src_assets!r}"
    )
    assert dst_assets[0]["hashes"]["SHA-256"] == digest, (
        f"the destination recorded SHA-256 {dst_assets[0]['hashes']['SHA-256']!r} for bytes "
        f"hashing to {digest!r}"
    )

    origin = ca.describe_package_version(
        domain=domain, repository=destination, format="generic", namespace=namespace,
        package=package, packageVersion="1.0.0")["packageVersion"]["origin"]
    assert origin["domainEntryPoint"]["repositoryName"] == source, (
        f"the destination's origin names {origin['domainEntryPoint']!r}, expected the source "
        f"repository {source!r}"
    )

    # The source is not consumed by the copy.
    assert _asset(ca, domain, source, namespace, package) == payload, (
        "the source asset changed as a side effect of the copy"
    )


def _asset(ca, domain: str, repository: str, namespace: str, package: str) -> bytes:
    """The stored bytes of the one asset of version 1.0.0 in `repository`."""
    return ca.get_package_version_asset(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=package, packageVersion="1.0.0", asset="payload.bin")["asset"].read()


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
