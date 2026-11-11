"""delete-package-with-existing-versions-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-package-with-existing-versions-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """DeletePackage fails with ValidationException while a version still exists under
    the package, the package remains fully intact (GetPackage still succeeds), and
    deleting the version first lets the subsequent DeletePackage succeed."""
    iot = ctx.client("iot")
    _ensure_package_indexing_active(ctx)
    package_name = ctx.unique_name("sim2real-pkg-delcheck-")
    _create_package_retry(iot, package_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _delete_package_quiet(ctx, package_name))

    version_name = "v1"
    iot.create_package_version(
        packageName=package_name, versionName=version_name, tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(
        lambda: _delete_package_version_quiet(ctx, package_name, version_name)
    )

    code, message = _error_code(lambda: iot.delete_package(packageName=package_name))
    assert code == "ValidationException", (
        f"expected DeletePackage to reject a package with an existing version "
        f"with ValidationException, got {code!r}"
    )
    expected_message = f"Unable to delete package '{package_name}' as there are package versions associated with it"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Absence of effect: the package is still there, untouched.
    still_there = iot.get_package(packageName=package_name)
    assert still_there["packageName"] == package_name, (
        f"expected {package_name!r} to survive the rejected delete, got "
        f"{still_there.get('packageName')!r}"
    )

    # Positive control: deleting the version first allows DeletePackage to succeed.
    iot.delete_package_version(packageName=package_name, versionName=version_name)
    iot.delete_package(packageName=package_name)

    gone_code, gone_message = _error_code(lambda: iot.get_package(packageName=package_name))
    assert gone_code == "ResourceNotFoundException", (
        f"expected GetPackage on the deleted {package_name!r} to raise "
        f"ResourceNotFoundException, got {gone_code!r}"
    )
    expected_gone = f"Package {package_name} not found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"

    # A mutation on the now-dead package also fails, not just the read. IoT reports this
    # as ValidationException (the package itself is gone), not ResourceNotFoundException.
    dead_mutation_code, dead_mutation_message = _error_code(
        lambda: iot.delete_package_version(
            packageName=package_name, versionName=version_name
        )
    )
    assert dead_mutation_code == "ValidationException", (
        f"expected DeletePackageVersion against the deleted {package_name!r} to "
        f"raise ValidationException, got {dead_mutation_code!r}"
    )
    expected_dead = f"Package with packageName: {package_name} not found"
    assert dead_mutation_message == expected_dead, (
        f"expected message {expected_dead!r}, got {dead_mutation_message!r}"
    )


# ===== helpers =====
def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_package_version_quiet(ctx, package_name, version_name):
    """Teardown: delete the version; a missing version or package (ValidationException
    '... not found') counts as clean, anything else raises."""
    from botocore.exceptions import ClientError

    iot = ctx.client("iot")
    try:
        iot.delete_package_version(packageName=package_name, versionName=version_name)
    except ClientError as exc:
        err = exc.response["Error"]
        gone = err["Code"] == "ResourceNotFoundException" or (
            err["Code"] == "ValidationException" and err.get("Message", "").endswith("not found")
        )
        if not gone:
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


def _create_package_retry(iot, package_name, tags=None, timeout_s=120.0, interval_s=5.0):
    """CreatePackage can trail the fleet-indexing config becoming ACTIVE by a short
    propagation window; retry on the specific ValidationException it raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_package(packageName=package_name, tags=tags or {})
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
