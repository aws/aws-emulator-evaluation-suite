"""package-version-metadata-unicode-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-version-metadata-unicode-round-trip"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """Unicode description/attribute/tag values on a package version survive GetPackageVersion
    and ListTagsForResource unchanged, byte-for-byte (no mojibake, no truncation, no escaping
    drift)."""
    iot = ctx.client("iot")
    package_name = ctx.unique_name("sim2real-iot-pkg-")
    version_name = "v1"

    description = "Unicode desc: caf\u00e9 \u65e5\u672c\u8a9e \U0001F680 \u2764 \u00df\u00f1"
    attributes = {
        "note": "unicode-caf\u00e9-\u65e5\u672c\u8a9e-\U0001F680-\u00df\u00f1-end",
        "region-note": "\u0645\u0646\u0637\u0642\u0629 \u0627\u0644\u0634\u0631\u0642",
    }
    tags = {
        "team": "sim2real-caf\u00e9",
        "\u90e8\u9580": "iot",
    }

    _ensure_package_fleet_indexing(ctx, iot)
    _create_package_with_retry(iot, package_name, timeout_s=60.0)
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))

    iot.create_package_version(
        packageName=package_name,
        versionName=version_name,
        description=description,
        attributes=attributes,
        tags=tags,
    )
    ctx.on_cleanup(
        lambda: iot.delete_package_version(packageName=package_name, versionName=version_name)
    )

    got = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert got["description"] == description, (got["description"], description)
    assert got["attributes"] == attributes, (got["attributes"], attributes)

    tags_resp = iot.list_tags_for_resource(resourceArn=got["packageVersionArn"])
    returned_tags = {t["Key"]: t["Value"] for t in tags_resp["tags"]}
    for key, value in tags.items():
        assert returned_tags.get(key) == value, (key, returned_tags.get(key), value)


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
            iot.create_package(packageName=package_name)
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
