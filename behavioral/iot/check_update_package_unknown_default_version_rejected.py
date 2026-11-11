"""update-package-unknown-default-version-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-package-unknown-default-version-rejected"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """UpdatePackage rejects a defaultVersionName that references a version which does not
    exist on the package, leaves the package's default version untouched, and a subsequent
    UpdatePackage with a real version name still succeeds."""
    iot = ctx.client("iot")

    # CreatePackage requires fleet indexing to be enabled on the reserved "$package" named
    # shadow (Software Package Catalog data source) before any package can be created.
    original_thing_indexing = iot.get_indexing_configuration().get(
        "thingIndexingConfiguration", {}
    )

    def _restore_indexing():
        iot.update_indexing_configuration(thingIndexingConfiguration=original_thing_indexing)

    ctx.on_cleanup(_restore_indexing)

    named_shadow_names = original_thing_indexing.get("filter", {}).get("namedShadowNames", [])
    new_thing_indexing = {
        "thingIndexingMode": "REGISTRY_AND_SHADOW",
        "namedShadowIndexingMode": "ON",
        "filter": {"namedShadowNames": sorted(set(named_shadow_names) | {"$package"})},
    }
    if original_thing_indexing.get("thingConnectivityIndexingMode"):
        new_thing_indexing["thingConnectivityIndexingMode"] = original_thing_indexing[
            "thingConnectivityIndexingMode"
        ]
    iot.update_indexing_configuration(thingIndexingConfiguration=new_thing_indexing)
    _poll_until(
        lambda: iot.describe_index(indexName="AWS_Things")["indexStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60.0,
    )

    package_name = ctx.unique_name("sim2real-iot-pkg-neg-")
    iot.create_package(packageName=package_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))

    version_name = "v1"
    iot.create_package_version(
        packageName=package_name, versionName=version_name, tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(
        lambda: iot.delete_package_version(packageName=package_name, versionName=version_name)
    )
    # Only a Published (or Deprecated) version may be set as a package's default version.
    iot.update_package_version(
        packageName=package_name, versionName=version_name, action="PUBLISH"
    )
    _poll_until(
        lambda: iot.get_package_version(packageName=package_name, versionName=version_name)[
            "status"
        ],
        lambda status: status == "PUBLISHED",
        timeout_s=30.0,
    )

    bogus_version_name = "does-not-exist"
    code, message = _error_code(
        lambda: iot.update_package(
            packageName=package_name,
            defaultVersionName=bogus_version_name,
            clientToken=str(uuid.uuid4()),
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"PackageVersion {bogus_version_name} for package {package_name} not found", message

    # Effect absence: the package still has no default version.
    unchanged = iot.get_package(packageName=package_name)
    assert not unchanged.get("defaultVersionName"), "default version must remain unset"

    # Positive control: setting a real version as default still works. A default version
    # cannot be deleted, so teardown unsets it before the version and package are removed.
    ctx.on_cleanup(
        lambda: iot.update_package(packageName=package_name, unsetDefaultVersion=True)
    )
    iot.update_package(
        packageName=package_name,
        defaultVersionName=version_name,
        clientToken=str(uuid.uuid4()),
    )
    updated = iot.get_package(packageName=package_name)
    assert updated["defaultVersionName"] == version_name, (
        f"expected defaultVersionName {version_name!r}, "
        f"got {updated.get('defaultVersionName')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error_code(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
