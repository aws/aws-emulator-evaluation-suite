"""list-package-versions-ordered-by-creation-time."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-package-versions-ordered-by-creation-time"
GROUP = "ordering"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """ListPackageVersions returns a package's versions sorted consistently with
    their own reported creationDate -- not an arbitrary/unstable order -- and that
    ordering is stable and repeatable across independent calls."""
    iot = ctx.client("iot")
    _ensure_package_indexing_active(ctx)
    package_name = ctx.unique_name("sim2realpkg")
    _create_package_retry(iot, package_name)
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))

    version_names = ["v1", "v2", "v3"]
    for version_name in version_names:
        iot.create_package_version(
            packageName=package_name,
            versionName=version_name,
            tags=_mgmt_tags(),
        )
        ctx.on_cleanup(
            lambda v=version_name: iot.delete_package_version(packageName=package_name, versionName=v)
        )
        time.sleep(1.5)  # keep creationDate timestamps distinct between versions

    listing_1 = iot.list_package_versions(packageName=package_name)["packageVersionSummaries"]
    listing_2 = iot.list_package_versions(packageName=package_name)["packageVersionSummaries"]
    names_1 = [v["versionName"] for v in listing_1]
    names_2 = [v["versionName"] for v in listing_2]
    dates_1 = [v["creationDate"] for v in listing_1]

    expected_names = [
        v["versionName"]
        for v in sorted(listing_1, key=lambda v: v["creationDate"], reverse=True)
    ]
    assert names_1 == expected_names, (
        f"ListPackageVersions order must match a descending sort of the "
        f"summaries' own reported creationDate: got {names_1} for dates {dates_1}, "
        f"expected {expected_names}"
    )
    assert set(names_1) == set(version_names), (
        f"expected exactly {version_names}, got {names_1}"
    )
    assert names_2 == names_1, (
        f"ListPackageVersions must return a stable, repeatable order across "
        f"independent calls: first call {names_1}, second call {names_2}"
    )


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2realpkg"}


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
            iot.create_package(packageName=package_name, tags=_mgmt_tags())
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
