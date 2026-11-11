"""package-version-duplicate-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "package-version-duplicate-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """CreatePackageVersion with a version name that already exists for the package
    returns ConflictException instead of silently overwriting the existing version's
    fields, while creating a genuinely new version name for the same package succeeds."""
    iot = ctx.client("iot")
    resource_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pkg"}
    _ensure_package_indexing_active(ctx)
    package_name = ctx.unique_name("sim2real-pkg-")
    _create_package_retry(iot, package_name, tags=resource_tags)
    ctx.on_cleanup(lambda: _delete_package_quiet(ctx, package_name))

    version_name = "v1"
    first = iot.create_package_version(
        packageName=package_name,
        versionName=version_name,
        description="first-description",
        tags=resource_tags,
    )
    ctx.on_cleanup(
        lambda: _delete_package_version_quiet(ctx, package_name, version_name)
    )
    first_arn = first["packageVersionArn"]

    code, message = _error_code(
        lambda: iot.create_package_version(
            packageName=package_name,
            versionName=version_name,
            description="second-description-should-not-land",
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = (
        "Conditional check failure: Received duplicate request for package "
        f"{package_name} version {version_name}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = iot.get_package_version(
        packageName=package_name, versionName=version_name
    )
    assert unchanged["description"] == "first-description", (
        f"expected description to remain 'first-description' after the rejected "
        f"duplicate create, got {unchanged['description']!r}"
    )
    assert unchanged["packageVersionArn"] == first_arn, (
        f"expected packageVersionArn to remain {first_arn!r} after the rejected "
        f"duplicate create, got {unchanged['packageVersionArn']!r}"
    )

    # Positive control: a distinct version name for the same package succeeds.
    other_version_name = "v2"
    iot.create_package_version(
        packageName=package_name,
        versionName=other_version_name,
        description="second-version",
        tags=resource_tags,
    )
    ctx.on_cleanup(
        lambda: _delete_package_version_quiet(ctx, package_name, other_version_name)
    )
    created_other = iot.get_package_version(
        packageName=package_name, versionName=other_version_name
    )
    assert created_other["description"] == "second-version", (
        f"expected the distinct version name {other_version_name!r} to succeed with "
        f"its own description, got {created_other['description']!r}"
    )


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _create_package_retry(iot, package_name, tags=None, timeout_s=120.0, interval_s=5.0):
    """CreatePackage can trail the fleet-indexing config becoming ACTIVE by a short
    propagation window; retry on the specific ValidationException it raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            if tags:
                iot.create_package(packageName=package_name, tags=tags)
            else:
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
