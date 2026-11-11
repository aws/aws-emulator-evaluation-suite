"""codeartifact-publish-with-mismatched-asset-sha256-rejected-and-version-absent."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "codeartifact-publish-with-mismatched-asset-sha256-rejected-and-version-absent"
GROUP = 'publish'
SERVICES = ['codeartifact']


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A publish whose assetSHA256 differs by one hex character is refused with ValidationException
    and leaves the package absent; the same bytes under the true digest publish and read back exact.
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
    package = ctx.unique_name("sim2real-digest-")
    blob = bytes((i * 97 + 13) % 251 for i in range(8192))
    true_digest = hashlib.sha256(blob).hexdigest()
    # Break exactly one thing: one hex character of the declared digest.
    wrong_digest = ("0" if true_digest[0] != "0" else "1") + true_digest[1:]
    assert wrong_digest != true_digest and len(wrong_digest) == len(true_digest), (
        f"the fixture failed to build a one-character mismatch: {wrong_digest!r}"
    )

    code, message = _rejection(lambda: ca.publish_package_version(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=package, packageVersion="1.0.0", assetContent=blob, assetName="payload.bin",
        assetSHA256=wrong_digest))
    assert code == "ValidationException", (
        f"expected ValidationException for a digest mismatch, got {code!r}: {message!r}"
    )
    expected_message = (
        f"The provided content hashes do not match the calculated content hashes. Hash algorithm "
        f"'SHA-256', Expected hash '{wrong_digest}', Actual hash '{true_digest}'"
    )
    assert message == expected_message, (
        f"the rejection message is {message!r}, expected {expected_message!r}: it names the "
        f"declared digest and the hash the service actually calculated"
    )

    absent_code, absent_message = _rejection(lambda: ca.list_package_versions(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=package))
    expected_absent = (
        f"The generic package '{package}' with namespace '{namespace}' does not exist in "
        f"repository '{repository}'."
    )
    assert (absent_code, absent_message) == ("ResourceNotFoundException", expected_absent), (
        f"a package version survived the rejected publish: ListPackageVersions answered "
        f"{absent_code!r}: {absent_message!r}, expected ResourceNotFoundException: "
        f"{expected_absent!r}"
    )

    # Positive control: the identical bytes under the true digest publish and read back exactly.
    good = ca.publish_package_version(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=package, packageVersion="1.0.0", assetContent=blob, assetName="payload.bin",
        assetSHA256=true_digest)
    assert (good["version"], good["status"]) == ("1.0.0", "Published"), (
        f"the corrected publish returned version {good['version']!r} status "
        f"{good['status']!r}, expected ('1.0.0', 'Published')"
    )
    assert good["asset"]["hashes"]["SHA-256"] == true_digest, (
        f"PublishPackageVersion echoed asset hashes {good['asset']['hashes']!r}, expected "
        f"SHA-256 {true_digest!r}"
    )
    stored = ca.get_package_version_asset(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=package, packageVersion="1.0.0", asset="payload.bin")["asset"].read()
    assert stored == blob, (
        f"stored {len(stored)!r} bytes (sha256 {hashlib.sha256(stored).hexdigest()!r}) for a "
        f"{len(blob)!r}-byte publish (sha256 {true_digest!r})"
    )
    assets = _paginate(ca.list_package_version_assets, "assets", domain=domain,
                      repository=repository, format="generic", namespace=namespace,
                      package=package, packageVersion="1.0.0")
    assert [a["hashes"]["SHA-256"] for a in assets] == [true_digest], (
        f"the recorded asset hashes are {[a['hashes'] for a in assets]!r}, expected exactly one "
        f"asset hashing to {true_digest!r}"
    )


def _rejection(fn) -> tuple[str, str]:
    """The (code, message) of a call that MUST be rejected; raises if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"the call was expected to be rejected but returned {result!r}")


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
