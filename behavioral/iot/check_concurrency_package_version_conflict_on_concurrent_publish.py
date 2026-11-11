"""concurrency-package-version-conflict-on-concurrent-publish."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrency-package-version-conflict-on-concurrent-publish"
GROUP = "concurrency"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """Racing CreatePackageVersion calls for the same version yield one winner and
    ConflictException for the rest; the winner's DRAFT description survives the update
    to PUBLISHED."""
    iot = ctx.client("iot")

    _ensure_package_indexing_active(ctx, iot)
    package_name = ctx.unique_name("sim2real-pkg")
    _create_package_retry(iot, package_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))

    version_name = "v1"
    racer_count = 6

    def _racer(i: int):
        try:
            iot.create_package_version(
                packageName=package_name,
                versionName=version_name,
                description=f"racer-{i}",
            )
            return ("ok", i)
        except ClientError as e:
            return (e.response["Error"]["Code"], i)

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    ctx.on_cleanup(lambda: iot.delete_package_version(packageName=package_name, versionName=version_name))

    successes = [r for r in results if r[0] == "ok"]
    conflicts = [r for r in results if r[0] == "ConflictException"]
    assert len(successes) == 1, f"expected exactly one winning create, got: {results}"
    assert len(conflicts) == racer_count - 1, f"expected the rest to conflict, got: {results}"

    winner_index = successes[0][1]
    got = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert got["status"] == "DRAFT", got
    assert got["description"] == f"racer-{winner_index}", got
    iot.tag_resource(resourceArn=got["packageVersionArn"], tags=[{"Key": "sim2real", "Value": CHECK}])

    # No lost update: the winner's data survives the status transition.
    iot.update_package_version(packageName=package_name, versionName=version_name, action="PUBLISH")
    got_after = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert got_after["status"] == "PUBLISHED", got_after
    assert got_after["description"] == f"racer-{winner_index}", got_after


def _ensure_package_indexing_active(ctx, iot, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """CreatePackage requires fleet indexing enabled with the reserved '$package'
    named shadow as a data source; enable it idempotently and wait for the
    AWS_Things index to report ACTIVE before proceeding."""
    current = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})
    named_shadow_names = current.get("filter", {}).get("namedShadowNames", [])
    already_ready = current.get("namedShadowIndexingMode") == "ON" and "$package" in named_shadow_names
    if not already_ready:
        thing_mode = current.get("thingIndexingMode")
        if thing_mode not in ("REGISTRY", "REGISTRY_AND_SHADOW"):
            thing_mode = "REGISTRY"
        new_cfg = {
            "thingIndexingMode": thing_mode,
            "namedShadowIndexingMode": "ON",
            "filter": {"namedShadowNames": sorted(set(named_shadow_names) | {"$package"})},
        }
        ctx.on_cleanup(_restore_thing_indexing(iot, current))
        iot.update_indexing_configuration(thingIndexingConfiguration=new_cfg)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if iot.describe_index(indexName="AWS_Things")["indexStatus"] == "ACTIVE":
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


def _create_package_retry(
    iot, package_name: str, tags=None, timeout_s: float = 120.0, interval_s: float = 5.0
) -> None:
    """CreatePackage can trail the fleet-indexing config becoming ACTIVE by a short
    propagation window; retry only on that specific ValidationException."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_package(packageName=package_name, tags=tags or {})
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "fleet indexing" in message.lower() and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
