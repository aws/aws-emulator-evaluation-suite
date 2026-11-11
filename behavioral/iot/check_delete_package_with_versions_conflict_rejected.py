"""delete-package-with-versions-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-package-with-versions-conflict-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """DeletePackage on a package with a version fails with ValidationException and its
    exact message and the package stays; after deleting the version the package delete
    succeeds and GetPackage fails with ResourceNotFoundException."""
    iot = ctx.client("iot")
    package_name = ctx.unique_name("sim2real-pkgdel-")
    version_name = "v1"

    _ensure_package_indexing(ctx, iot)
    iot.create_package(packageName=package_name, tags={"sim2real": CHECK})
    package_cleaned = {"done": False}

    def _cleanup_package():
        if not package_cleaned["done"]:
            iot.delete_package(packageName=package_name)

    ctx.on_cleanup(_cleanup_package)

    iot.create_package_version(packageName=package_name, versionName=version_name)

    code, message = _error_code(lambda: iot.delete_package(packageName=package_name))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = f"Unable to delete package '{package_name}' as there are package versions associated with it"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the package must still exist (not deleted)
    got = iot.get_package(packageName=package_name)
    assert got["packageName"] == package_name

    # break the one dependency and confirm the positive control now succeeds
    iot.delete_package_version(packageName=package_name, versionName=version_name)
    iot.delete_package(packageName=package_name)
    package_cleaned["done"] = True

    # independent terminal read: the package is actually gone, not just accepted
    gone_code, gone_message = _error_code(lambda: iot.get_package(packageName=package_name))
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {gone_code}"
    expected_gone = f"Package {package_name} not found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"

def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
