"""package-default-version-reflected-in-get-package."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "package-default-version-reflected-in-get-package"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """UpdatePackage setting defaultVersionName causes GetPackage to report that
    version as the default, GetPackageVersion for the two versions never cross-report
    each other's identity, and unsetDefaultVersion clears it again."""
    iot = ctx.client("iot")
    _ensure_package_indexing_active(ctx)
    package_name = ctx.unique_name("sim2real-pkg-default-")
    _create_package_retry(iot, package_name)
    ctx.on_cleanup(lambda: _delete_package_quiet(ctx, package_name))

    iot.create_package_version(packageName=package_name, versionName="v1")
    ctx.on_cleanup(lambda: _delete_package_version_quiet(ctx, package_name, "v1"))
    iot.create_package_version(packageName=package_name, versionName="v2")
    ctx.on_cleanup(lambda: _delete_package_version_quiet(ctx, package_name, "v2"))

    # A package version must be PUBLISHED before it can be named the package default.
    iot.update_package_version(
        packageName=package_name, versionName="v1", action="PUBLISH"
    )
    iot.update_package_version(
        packageName=package_name, versionName="v2", action="PUBLISH"
    )

    before = iot.get_package(packageName=package_name)
    assert before.get("defaultVersionName", "") == ""

    iot.update_package(packageName=package_name, defaultVersionName="v2")
    after = iot.get_package(packageName=package_name)
    assert after["defaultVersionName"] == "v2"

    iot.update_package(packageName=package_name, defaultVersionName="v1")
    switched = iot.get_package(packageName=package_name)
    assert switched["defaultVersionName"] == "v1"

    # Both versions have now held the default pointer; each must still report its own
    # identity rather than the other's.
    v1_read = iot.get_package_version(packageName=package_name, versionName="v1")
    assert v1_read["versionName"] == "v1", v1_read
    v2_read = iot.get_package_version(packageName=package_name, versionName="v2")
    assert v2_read["versionName"] == "v2", v2_read

    iot.update_package(packageName=package_name, unsetDefaultVersion=True)
    cleared = iot.get_package(packageName=package_name)
    assert cleared.get("defaultVersionName", "") == "", f"unexpected: {cleared.get('defaultVersionName')!r}"


def _delete_package_version_quiet(ctx, package_name, version_name):
    """Teardown: delete one package version; a missing version is clean, anything else raises."""
    from botocore.exceptions import ClientError

    iot = ctx.client("iot")
    try:
        iot.delete_package_version(packageName=package_name, versionName=version_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_package_quiet(ctx, package_name):
    iot = ctx.client("iot")
    iot.delete_package(packageName=package_name)


def _ensure_package_indexing_active(ctx, timeout_s=180.0, interval_s=5.0):
    """The Software Package Catalog requires fleet indexing enabled with the reserved
    $package named shadow as a data source before CreatePackage will succeed."""
    from botocore.exceptions import ClientError

    iot = ctx.client("iot")
    current = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})
    named_shadow_names = current.get("filter", {}).get("namedShadowNames", [])
    already_ready = (
        current.get("thingIndexingMode") == "REGISTRY_AND_SHADOW"
        and current.get("namedShadowIndexingMode") == "ON"
        and "$package" in named_shadow_names
    )
    if not already_ready:
        new_cfg = {
            "thingIndexingMode": "REGISTRY_AND_SHADOW",
            "namedShadowIndexingMode": "ON",
            "thingConnectivityIndexingMode": current.get(
                "thingConnectivityIndexingMode", "OFF"
            ),
            "filter": {"namedShadowNames": sorted(set(named_shadow_names) | {"$package"})},
        }
        if current.get("customFields"):
            new_cfg["customFields"] = current["customFields"]
        ctx.on_cleanup(_restore_thing_indexing(iot, current))
        try:
            iot.update_indexing_configuration(thingIndexingConfiguration=new_cfg)
        except ClientError:
            pass
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = iot.describe_index(indexName="AWS_Things")["indexStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError("AWS_Things index never reached ACTIVE within timeout")


def _restore_thing_indexing(iot, prior):
    """Teardown for the account-wide thing indexing configuration: put back exactly the
    configuration read before this check changed it. managedFields is derived by the service
    from the modes, so it is not sent back."""
    import copy

    original = {k: v for k, v in copy.deepcopy(prior).items() if k != "managedFields"}
    original.setdefault("thingIndexingMode", "OFF")
    return lambda: iot.update_indexing_configuration(thingIndexingConfiguration=original)


def _create_package_retry(iot, package_name, timeout_s=120.0, interval_s=5.0):
    """CreatePackage can trail the fleet-indexing config becoming ACTIVE by a short
    propagation window; retry on the specific ValidationException it raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_package(packageName=package_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "fleet indexing" in msg.lower() and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
