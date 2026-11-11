"""concurrent-package-version-default-update-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-package-version-default-update-conflict"
GROUP = "concurrency"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """Two concurrent UpdatePackage calls setting different default versions must
    resolve to exactly one stable winner: the defaultVersionName pointer never ends up
    unset, corrupted, or flapping between reads once the race has settled."""
    iot = ctx.client("iot")
    original_indexing = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})
    ctx.on_cleanup(lambda: iot.update_indexing_configuration(thingIndexingConfiguration=original_indexing))
    _ensure_package_indexing_active(iot, original_indexing)

    package_name = ctx.unique_name("sim2real-pkg-")
    _create_package_retry(iot, package_name)
    ctx.on_cleanup(lambda: _delete_package(iot, package_name))

    for version in ("v1", "v2"):
        iot.create_package_version(packageName=package_name, versionName=version)
        # A package version must be PUBLISHED before it is eligible to become the
        # package's default version -- a DRAFT version cannot be set as default.
        iot.update_package_version(packageName=package_name, versionName=version, action="PUBLISH")

    barrier = threading.Barrier(2)

    def _set_default(version: str) -> None:
        barrier.wait()
        iot.update_package(packageName=package_name, defaultVersionName=version)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_set_default, v) for v in ("v1", "v2")]
        for f in futures:
            f.result()  # UpdatePackage documents no conflict error; both calls succeed

    observed = set()
    for _ in range(10):
        observed.add(iot.get_package(packageName=package_name)["defaultVersionName"])
    assert len(observed) == 1, f"defaultVersionName flapped across reads: {observed}"
    winner = next(iter(observed))
    assert winner in ("v1", "v2"), f"defaultVersionName corrupted: {winner!r}"


# ===== helpers =====

def _ensure_package_indexing_active(iot, current: dict, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """CreatePackage requires fleet indexing enabled with the reserved $package named
    shadow (Software Package Catalog data source) before it will succeed."""
    named_shadow_names = current.get("filter", {}).get("namedShadowNames", [])
    already_ready = (
        current.get("thingIndexingMode") in ("REGISTRY", "REGISTRY_AND_SHADOW")
        and current.get("namedShadowIndexingMode") == "ON"
        and "$package" in named_shadow_names
    )
    if not already_ready:
        mode = current.get("thingIndexingMode")
        iot.update_indexing_configuration(
            thingIndexingConfiguration={
                "thingIndexingMode": mode if mode in ("REGISTRY", "REGISTRY_AND_SHADOW") else "REGISTRY_AND_SHADOW",
                "namedShadowIndexingMode": "ON",
                "filter": {"namedShadowNames": sorted(set(named_shadow_names) | {"$package"})},
            }
        )
    deadline = time.monotonic() + timeout_s
    while True:
        status = iot.describe_index(indexName="AWS_Things")["indexStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"AWS_Things index never reached ACTIVE within {timeout_s}s; last={status!r}")
        time.sleep(interval_s)


def _create_package_retry(iot, package_name: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    """CreatePackage can trail the fleet-indexing config becoming ACTIVE by a short
    propagation window; retry on the specific ValidationException it raises."""
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


def _delete_package(iot, package_name: str) -> None:
    try:
        iot.update_package(packageName=package_name, unsetDefaultVersion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        versions = iot.list_package_versions(packageName=package_name).get(
            "packageVersionSummaries", []
        )
        for v in versions:
            try:
                iot.delete_package_version(packageName=package_name, versionName=v["versionName"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    iot.delete_package(packageName=package_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
