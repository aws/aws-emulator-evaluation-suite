"""codeartifact-package-origin-configuration-blocks-direct-publish."""
from __future__ import annotations

import hashlib
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "codeartifact-package-origin-configuration-blocks-direct-publish"
GROUP = 'overly-permissive'
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
    """With publish=BLOCK, publishing the next version fails with ValidationException and its exact
    message and stores nothing, while an unrestricted sibling publishes; restoring publish=ALLOW
    lets the identical publish land with its bytes."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-capubblock-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    namespace = "sim2real-ns"
    blocked = ctx.unique_name("sim2real-blocked-")
    allowed = ctx.unique_name("sim2real-allowed-")
    v1 = b"sim2real generic asset v1: published before the restriction\n"
    v2 = b"sim2real generic asset v2: must never be stored\n"

    # The package must exist first, so the restriction is the only thing that changes.
    ca.publish_package_version(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=blocked, packageVersion="1.0.0", assetContent=v1, assetName="asset.bin",
        assetSHA256=hashlib.sha256(v1).hexdigest())

    ca.put_package_origin_configuration(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=blocked, restrictions={"publish": "BLOCK", "upstream": "ALLOW"})
    restrictions = _poll(
        lambda: ca.describe_package(
            domain=domain, repository=repository, format="generic", namespace=namespace,
            package=blocked)["package"].get("originConfiguration", {}).get("restrictions", {}),
        lambda r: r.get("publish") == "BLOCK", timeout_s=60.0, interval_s=3.0)
    assert restrictions.get("publish") == "BLOCK", (
        f"the publish restriction never became BLOCK: {restrictions!r}"
    )

    code, message = _rejection(lambda: ca.publish_package_version(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=blocked, packageVersion="2.0.0", assetContent=v2, assetName="asset.bin",
        assetSHA256=hashlib.sha256(v2).hexdigest()))
    # Real AWS answers ValidationException here, not the ConflictException the origin-controls
    # narrative documentation suggests, and the reason text names the restriction.
    assert code == "ValidationException", (
        f"expected ValidationException for a publish blocked by the origin configuration, got "
        f"{code!r}: {message!r}"
    )
    expected_message = "This package is configured to block new versions from being published."
    assert message == expected_message, (
        f"the rejection message is {message!r}, expected {expected_message!r}"
    )

    # Effect absent: 2.0.0 exists nowhere, and its bytes are not readable under any name.
    versions = {v["version"] for v in _paginate(
        ca.list_package_versions, "versions", domain=domain, repository=repository,
        format="generic", namespace=namespace, package=blocked)}
    assert versions == {"1.0.0"}, (
        f"the repository holds {sorted(versions)!r} after the blocked publish, expected only the "
        f"pre-restriction 1.0.0"
    )
    # The message embeds the repository's internal repoId, which no API returns; it is masked.
    absent = _rejection(lambda: ca.get_package_version_asset(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=blocked, packageVersion="2.0.0", asset="asset.bin"))
    expected_absent = (
        "ResourceNotFoundException",
        f"Package version not found in repo. repoId = '<id>', packageCoordinate = "
        f"'PackageVersionCoordinateEntity{{name={blocked}, type=GENERIC, namespace={namespace}, version=2.0.0, "
        f"displayName={namespace}/{blocked}/2.0.0}}'.",
    )
    assert absent == expected_absent, (
        f"the blocked version's asset is readable or refused otherwise: GetPackageVersionAsset "
        f"answered {absent!r}, expected {expected_absent!r}"
    )
    surviving = ca.get_package_version_asset(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=blocked, packageVersion="1.0.0", asset="asset.bin")["asset"].read()
    assert surviving == v1, (
        f"the pre-restriction version's bytes changed to {surviving!r}, expected {v1!r}"
    )

    # Restore leg: this is a broken-then-restored negative (a state that forbids, not an
    # always-invalid input), so the switch must be shown reversible — the identical call must
    # now land.
    ca.put_package_origin_configuration(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=blocked, restrictions={"publish": "ALLOW", "upstream": "ALLOW"})
    restored = _poll(
        lambda: ca.describe_package(
            domain=domain, repository=repository, format="generic", namespace=namespace,
            package=blocked)["package"].get("originConfiguration", {}).get("restrictions", {}),
        lambda r: r.get("publish") == "ALLOW", timeout_s=60.0, interval_s=3.0)
    assert restored.get("publish") == "ALLOW", (
        f"the publish restriction never returned to ALLOW: {restored!r}"
    )
    landed = ca.publish_package_version(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=blocked, packageVersion="2.0.0", assetContent=v2, assetName="asset.bin",
        assetSHA256=hashlib.sha256(v2).hexdigest())
    assert (landed["version"], landed["status"]) == ("2.0.0", "Published"), (
        f"the identical publish after restoring publish=ALLOW returned {landed['version']!r} / "
        f"{landed['status']!r}, expected 2.0.0 / Published"
    )
    restored_bytes = ca.get_package_version_asset(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=blocked, packageVersion="2.0.0", asset="asset.bin")["asset"].read()
    assert restored_bytes == v2, (
        f"the restored publish stored {restored_bytes!r}, expected {v2!r}"
    )

    # Positive control: an unrestricted sibling in the same repository publishes and reads back.
    published = ca.publish_package_version(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=allowed, packageVersion="1.0.0", assetContent=v2, assetName="asset.bin",
        assetSHA256=hashlib.sha256(v2).hexdigest())
    assert (published["version"], published["status"]) == ("1.0.0", "Published"), (
        f"the unrestricted sibling publish returned {published['version']!r} / "
        f"{published['status']!r}"
    )
    control_bytes = ca.get_package_version_asset(
        domain=domain, repository=repository, format="generic", namespace=namespace,
        package=allowed, packageVersion="1.0.0", asset="asset.bin")["asset"].read()
    assert control_bytes == v2, (
        f"the unrestricted sibling stored {control_bytes!r}, published {v2!r} — the same bytes "
        f"the blocked package was refused"
    )


def _rejection(fn) -> tuple[str, str]:
    """The (code, message) of a call that MUST be rejected, the internal id masked; raises if
    it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], _mask_internal_id(error.get("Message", ""))
    raise AssertionError(f"the call was expected to be rejected but returned {result!r}")


_INTERNAL_ID = re.compile(r"(repoId = '|domainId=)[0-9a-f-]{36}")


def _mask_internal_id(message: str) -> str:
    """Mask the service-internal repository or domain id, which no CodeArtifact API returns."""
    return _INTERNAL_ID.sub(r"\1<id>", message)


def _paginate(operation, key: str, **kwargs) -> list[dict]:
    """Every page of a CodeArtifact List* call."""
    out, next_token = [], None
    while True:
        page = operation(**kwargs, **({"nextToken": next_token} if next_token else {}))
        out.extend(page.get(key, []))
        next_token = page.get("nextToken")
        if not next_token:
            return out


def _poll(read, predicate, *, timeout_s: float, interval_s: float):
    """Bounded poll on an observable condition; returns the last read either way."""
    deadline = time.monotonic() + timeout_s
    while True:
        observed = read()
        if predicate(observed) or time.monotonic() >= deadline:
            return observed
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
