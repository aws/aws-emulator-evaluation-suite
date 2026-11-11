"""package-version-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-version-duplicate-name-rejected"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """CreatePackageVersion rejects a versionName that already exists under the same package
    with ConflictException, the original version's content is left untouched, and creating a
    distinct version name in the same package still succeeds."""
    iot = ctx.client("iot")

    _ensure_package_fleet_indexing(ctx, iot)

    package_name = ctx.unique_name("sim2real-iot-pkgdup-")
    version_name = "v1"

    _create_package_with_retry(iot, package_name, timeout_s=60.0)
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))

    first = iot.create_package_version(
        packageName=package_name, versionName=version_name, description="original"
    )
    ctx.on_cleanup(
        lambda: iot.delete_package_version(packageName=package_name, versionName=version_name)
    )
    first_arn = first["packageVersionArn"]

    code, message = _error_code(
        lambda: iot.create_package_version(
            packageName=package_name, versionName=version_name, description="duplicate-attempt"
        )
    )
    assert code == "ConflictException", code
    expected = (
        "Conditional check failure: Received duplicate request for package "
        f"{package_name} version {version_name}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the original version's identity and description were not overwritten
    got = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert got["packageVersionArn"] == first_arn, (got["packageVersionArn"], first_arn)
    assert got["description"] == "original", got["description"]

    # positive control: a distinct version name in the same package still succeeds
    version_name_2 = "v2"
    iot.create_package_version(
        packageName=package_name, versionName=version_name_2, description="second"
    )
    ctx.on_cleanup(
        lambda: iot.delete_package_version(packageName=package_name, versionName=version_name_2)
    )
    got2 = iot.get_package_version(packageName=package_name, versionName=version_name_2)
    assert got2["description"] == "second", got2["description"]


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected ConflictException, but the call SUCCEEDED and returned {result!r}")


def _ensure_package_fleet_indexing(ctx, iot) -> None:
    """Software Package Catalog requires fleet indexing with the reserved '$package' named shadow
    as a data source, else CreatePackage is a ValidationException. The setting is account-wide,
    so the prior thing indexing configuration is restored in teardown."""
    original = iot.get_indexing_configuration().get(
        "thingIndexingConfiguration", {"thingIndexingMode": "OFF"}
    )
    ctx.on_cleanup(lambda: iot.update_indexing_configuration(thingIndexingConfiguration=original))
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": "REGISTRY",
            "namedShadowIndexingMode": "ON",
            "filter": {"namedShadowNames": ["$package"]},
        }
    )


def _create_package_with_retry(iot, package_name, *, timeout_s):
    """The named-shadow-indexing config just applied can take a few seconds to propagate before
    CreatePackage accepts it; retry past that specific window instead of failing immediately."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            iot.create_package(
                packageName=package_name, tags={"sim2real:managed": "true"}
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code != "ValidationException" or "named shadow" not in message:
                raise
            last_error = exc
            time.sleep(3.0)
    raise AssertionError(f"package creation never succeeded: {last_error!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
