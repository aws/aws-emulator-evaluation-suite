"""package-version-asset-binary-blob-byte-equality."""
from __future__ import annotations

import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-version-asset-binary-blob-byte-equality"
GROUP = "server-side"
SERVICES = ["codeartifact"]


def _delete_domain(ca, domain, deadline=90.0):
    # DeleteDomain can return ConflictException for a window after the domain's last repository
    # is deleted — the account-level state has not yet caught up. ctx.on_cleanup swallows a raising
    # teardown, so an unretried call here silently leaks the domain.
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A published binary generic-format asset is retrievable via
    GetPackageVersionAsset with byte-for-byte equality to what was uploaded, and is
    enumerable via ListPackageVersionAssets with a matching size.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-caasset-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))

    repo = ctx.unique_name("repo-")
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    namespace = "sim2real-ns"
    package = ctx.unique_name("blobpkg-")
    version = "1.0.0"
    asset_name = "payload.bin"
    blob = os.urandom(4096)
    sha = hashlib.sha256(blob).hexdigest()

    ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        packageVersion=version,
        assetContent=blob,
        assetName=asset_name,
        assetSHA256=sha,
    )

    listed = ca.list_package_version_assets(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        packageVersion=version,
    )["assets"]
    matching = [a for a in listed if a["name"] == asset_name]
    assert len(matching) == 1, f"expected exactly one asset entry, got {listed}"
    assert matching[0]["size"] == len(blob), (
        f"listed asset size {matching[0]['size']}, expected {len(blob)}"
    )

    fetched = ca.get_package_version_asset(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        packageVersion=version,
        asset=asset_name,
    )
    fetched_bytes = fetched["asset"].read()
    assert fetched_bytes == blob, "fetched asset bytes differ from what was published"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
