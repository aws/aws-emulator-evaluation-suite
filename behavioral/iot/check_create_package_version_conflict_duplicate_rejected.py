"""create-package-version-conflict-duplicate-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-package-version-conflict-duplicate-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """Creating a package version name that already exists under the package is
    rejected with ConflictException, and the existing version is left untouched
    (not silently overwritten)."""
    iot = ctx.client("iot")
    package_name = ctx.unique_name("sim2real-pkg-")
    version_name = "v1"

    _ensure_package_indexing(ctx, iot)
    iot.create_package(packageName=package_name, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))

    first = iot.create_package_version(
        packageName=package_name, versionName=version_name, description="original"
    )
    ctx.on_cleanup(
        lambda: iot.delete_package_version(packageName=package_name, versionName=version_name)
    )
    first_arn = first["packageVersionArn"]

    err = _error(
        lambda: iot.create_package_version(
            packageName=package_name, versionName=version_name, description="duplicate-attempt"
        )
    )
    assert err == ("ConflictException", (
        "Conditional check failure: Received duplicate request for package "
        f"{package_name} version {version_name}"
    )), err

    # effect absent: the original version's description/arn must be unchanged
    got = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert got["packageVersionArn"] == first_arn, (
        f"expected unchanged arn {first_arn!r}, got {got['packageVersionArn']!r}"
    )
    assert got["description"] == "original", (
        f"expected description 'original', got {got['description']!r}"
    )

    # positive control: a genuinely new version name succeeds
    second_version = "v2"
    iot.create_package_version(packageName=package_name, versionName=second_version)
    ctx.on_cleanup(
        lambda: iot.delete_package_version(packageName=package_name, versionName=second_version)
    )
    got2 = iot.get_package_version(packageName=package_name, versionName=second_version)
    assert got2["versionName"] == second_version, (
        f"expected versionName {second_version!r}, got {got2['versionName']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ConflictException, but the call SUCCEEDED and returned {result!r}")


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
