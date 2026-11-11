"""generic-asset-roundtrip-is-byte-exact."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generic-asset-roundtrip-is-byte-exact"
GROUP = 'package-assets'
SERVICES = ['codeartifact']

# Deliberately not text: a NUL, a 0xFF that is invalid UTF-8, a CR/LF pair a naive
# transport would normalise, and a run of every byte value.
_PAYLOAD = b"\x00\xff\r\nsim2real" + bytes(range(256)) + b"\r\n\x00"


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A binary generic asset (NUL, 0xFF, CRLF, every byte value) is served back byte-exact with its
    name and revision, and the four listed hashes and the size match the payload recomputed locally."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-binary-asset"
    scope = dict(format="generic", namespace="sim2real", package=package)

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    published = ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", assetContent=_PAYLOAD,
        assetName="payload.bin", assetSHA256=hashlib.sha256(_PAYLOAD).hexdigest(), **scope)
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))
    assert published["asset"]["size"] == len(_PAYLOAD), (
        f"the publish response reports size {published['asset']['size']}, expected "
        f"{len(_PAYLOAD)}"
    )

    fetched = ca.get_package_version_asset(
        domain=domain, repository=repo, packageVersion="1.0.0", asset="payload.bin", **scope)
    served = fetched["asset"].read()
    assert served == _PAYLOAD, (
        f"the asset came back as {len(served)} bytes with sha256 "
        f"{hashlib.sha256(served).hexdigest()!r}, expected {len(_PAYLOAD)} bytes with "
        f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}"
    )
    assert fetched["assetName"] == "payload.bin", (
        f"the fetch echoed assetName {fetched['assetName']!r}, expected 'payload.bin'"
    )
    assert fetched["packageVersionRevision"] == published["versionRevision"], (
        f"the fetch reports revision {fetched['packageVersionRevision']!r} but the publish minted "
        f"{published['versionRevision']!r} — the asset must belong to the version that was published"
    )

    assets = []
    for page in ca.get_paginator("list_package_version_assets").paginate(
            domain=domain, repository=repo, packageVersion="1.0.0", **scope):
        assets.extend(page["assets"])
    assert [a["name"] for a in assets] == ["payload.bin"], (
        f"the asset listing returned {[a['name'] for a in assets]!r}, expected ['payload.bin']"
    )
    hashes = assets[0]["hashes"]
    expected = {
        "MD5": hashlib.md5(_PAYLOAD).hexdigest(),
        "SHA-1": hashlib.sha1(_PAYLOAD).hexdigest(),
        "SHA-256": hashlib.sha256(_PAYLOAD).hexdigest(),
        "SHA-512": hashlib.sha512(_PAYLOAD).hexdigest(),
    }
    assert hashes == expected, (
        f"the service's digests are {hashes!r}, but the payload's are {expected!r} — every "
        f"algorithm must describe the bytes actually stored"
    )
    assert assets[0]["size"] == len(_PAYLOAD), (
        f"the listing reports size {assets[0]['size']}, expected {len(_PAYLOAD)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
