"""update-package-version-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-package-version-nonexistent-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """UpdatePackageVersion on a version that was never created fails ResourceNotFoundException with the exact
    message and does not create it, while the same update on an existing version succeeds."""
    iot = ctx.client("iot")
    package_name = ctx.unique_name("sim2real-upv-pkg-")
    real_version = "v1"
    missing_version = "v-does-not-exist"

    _ensure_package_indexing(ctx, iot)
    iot.create_package(packageName=package_name)
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))

    iot.create_package_version(packageName=package_name, versionName=real_version)
    ctx.on_cleanup(
        lambda: iot.delete_package_version(packageName=package_name, versionName=real_version)
    )

    code, message = _error_code(
        lambda: iot.update_package_version(
            packageName=package_name,
            versionName=missing_version,
            description="should not be created",
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"PackageVersion {missing_version} for package {package_name} not found", message

    # effect absent: the nonexistent version must not have been created as a side effect
    code_after, message_after = _error_code(
        lambda: iot.get_package_version(packageName=package_name, versionName=missing_version)
    )
    assert code_after == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code_after}"
    )
    assert message_after == f"PackageVersion {missing_version} for package {package_name} not found", message_after

    # positive control: updating a version that does exist succeeds, and the effect
    # is visible via an independent read at the destination
    iot.update_package_version(
        packageName=package_name, versionName=real_version, description="updated-description"
    )
    updated = iot.get_package_version(packageName=package_name, versionName=real_version)
    assert updated["description"] == "updated-description", (
        f"expected description 'updated-description', got {updated.get('description')!r}"
    )

def _error_code(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
