"""package-version-update-conditional-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "package-version-update-conditional-conflict"
GROUP = "concurrency"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """Concurrent CreatePackageVersion calls for the SAME versionName: exactly one wins, every
    other racer gets ConflictException (never a silent overwrite), and the surviving version still
    accepts UpdatePackageVersion's lifecycle action."""
    iot = ctx.client("iot")
    _ensure_package_indexing_active(ctx)
    package_name = ctx.unique_name("sim2real-pkg-race-")
    _create_package_retry(iot, package_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _delete_package_quiet(ctx, package_name))

    version_name = "v1"
    ctx.on_cleanup(
        lambda: _delete_package_version_quiet(ctx, package_name, version_name)
    )

    racer_count = 6

    def _racer(i):
        try:
            iot.create_package_version(
                packageName=package_name,
                versionName=version_name,
                description=f"racer-{i}",
            )
            return ("ok", i)
        except Exception as exc:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
            raise

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_racer, i) for i in range(racer_count)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, f"expected {racer_count - 1} conflicts, got {results}"
    assert all(code == "ConflictException" for _, code, _msg in failures), failures
    expected = (
        f"Conditional check failure: Received duplicate request for package {package_name} "
        f"version {version_name}"
    )
    for _, _code, message in failures:
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    winner_i = successes[0][1]
    version = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert version["status"] == "DRAFT", version["status"]
    # No lost update: the surviving version's data is the winning racer's, not some
    # blend or a later loser's write sneaking through after the 200 was already denied.
    assert version["description"] == f"racer-{winner_i}", (version["description"], winner_i)
    # Tag once the race has settled -- tagging one of the six racers' own create calls
    # instead makes CreatePackageVersion itself fail with an unrelated tagging
    # ValidationException under real concurrent load, corrupting the signal under test.
    iot.tag_resource(
        resourceArn=version["packageVersionArn"], tags=[{"Key": "sim2real", "Value": CHECK}]
    )

    # Now drive the surviving version through its real lifecycle action.
    iot.update_package_version(
        packageName=package_name, versionName=version_name, action="PUBLISH"
    )
    published = iot.get_package_version(
        packageName=package_name, versionName=version_name
    )
    assert published["status"] == "PUBLISHED", published["status"]
    assert published["description"] == f"racer-{winner_i}", (published["description"], winner_i)


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


def _create_package_retry(iot, package_name, timeout_s=120.0, interval_s=5.0, tags=None):
    """CreatePackage can trail the fleet-indexing config becoming ACTIVE by a short
    propagation window; retry on the specific ValidationException it raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_package(packageName=package_name, **({"tags": tags} if tags else {}))
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
