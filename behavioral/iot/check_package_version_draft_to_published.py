"""package-version-draft-to-published."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "package-version-draft-to-published"
GROUP = 'package-lifecycle'
SERVICES = ['iot']

def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT propagates registry/job writes asynchronously, so the first few
    reads can raise ResourceNotFoundException before settling.
    """

    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """CreatePackageVersion starts in DRAFT; UpdatePackageVersion(action=PUBLISH)
    transitions it to PUBLISHED and that transition is durable."""
    iot = ctx.client("iot")
    package = ctx.unique_name("sim2real-behav-pkg-").replace("-", "_")
    version = "v1_0_0"

    _ensure_package_indexing(ctx, iot)
    iot.create_package(packageName=package, description="probe package", tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda _n=package: iot.delete_package(packageName=_n))

    pkg = iot.get_package(packageName=package)
    assert pkg["packageName"] == package, f"expected packageName {package}, got {pkg['packageName']!r}"

    iot.create_package_version(
        packageName=package, versionName=version, attributes={"build": "1"}
    )
    ctx.on_cleanup(
        lambda _p=package, _v=version: iot.delete_package_version(
            packageName=_p, versionName=_v
        )
    )

    got = iot.get_package_version(packageName=package, versionName=version)
    assert got["status"] == "DRAFT", f"new package version must start DRAFT, got {got['status']}"

    iot.update_package_version(
        packageName=package, versionName=version, action="PUBLISH"
    )
    published = _eventually(
        lambda: iot.get_package_version(packageName=package, versionName=version)["status"],
        lambda s: s == "PUBLISHED",
        timeout_s=60,
    )
    assert published == "PUBLISHED", published

    versions = [
        v["versionName"] for v in iot.list_package_versions(packageName=package).get("packageVersionSummaries", [])
    ]
    assert version in versions, f"{version} missing from ListPackageVersions"

    iot.update_package(packageName=package, description="updated package")
    updated_description = iot.get_package(packageName=package)["description"]
    assert updated_description == "updated package", f"expected updated description, got {updated_description!r}"

    names = [p["packageName"] for p in iot.list_packages().get("packageSummaries", [])]
    assert package in names, f"{package} missing from ListPackages"


def _ensure_package_indexing(ctx, iot) -> None:
    """CreatePackage requires fleet indexing enabled with the reserved '$package'
    named shadow as a data source; enable it idempotently if not already on."""
    current = iot.get_indexing_configuration()
    thing_cfg = current.get("thingIndexingConfiguration", {})
    named_shadow_names = thing_cfg.get("filter", {}).get("namedShadowNames", [])
    if thing_cfg.get("namedShadowIndexingMode") == "ON" and "$package" in named_shadow_names:
        return
    ctx.on_cleanup(_restore_thing_indexing(iot, thing_cfg))
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": "REGISTRY_AND_SHADOW",
            "namedShadowIndexingMode": "ON",
            "filter": {"namedShadowNames": sorted(set(named_shadow_names) | {"$package"})},
        }
    )


def _restore_thing_indexing(iot, prior):
    """Teardown for the account-wide thing indexing configuration: put back exactly the
    configuration read before this check changed it. managedFields is derived by the service
    from the modes, so it is not sent back."""
    import copy

    original = {k: v for k, v in copy.deepcopy(prior).items() if k != "managedFields"}
    original.setdefault("thingIndexingMode", "OFF")
    return lambda: iot.update_indexing_configuration(thingIndexingConfiguration=original)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
