"""package-configuration-default-version-enforced."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-configuration-default-version-enforced"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing", "resource:account-singleton:iot-package-configuration")
def run(ctx) -> None:
    """UpdatePackage(defaultVersionName=...) causes GetPackage to report that version as the
    package's default with no further per-version action, and the account-wide package
    configuration set via UpdatePackageConfiguration is reflected by GetPackageConfiguration."""
    iot = ctx.client("iot")

    # CreatePackage requires fleet indexing to be enabled on the reserved "$package" named
    # shadow (Software Package Catalog data source) before any package can be created. This
    # is an account/region-wide singleton, so adopt the existing config rather than replacing
    # it: preserve fields this check does not care about (thingConnectivityIndexingMode,
    # customFields, other named shadow filters) and skip the mutation entirely if the account
    # is already configured correctly.
    original_thing_indexing = iot.get_indexing_configuration().get(
        "thingIndexingConfiguration", {}
    )
    original_named_shadows = original_thing_indexing.get("filter", {}).get(
        "namedShadowNames", []
    )
    indexing_already_ready = (
        original_thing_indexing.get("thingIndexingMode") in ("REGISTRY", "REGISTRY_AND_SHADOW")
        and original_thing_indexing.get("namedShadowIndexingMode") == "ON"
        and "$package" in original_named_shadows
    )

    if not indexing_already_ready:
        new_thing_indexing = {
            "thingIndexingMode": (
                original_thing_indexing.get("thingIndexingMode")
                if original_thing_indexing.get("thingIndexingMode") in ("REGISTRY", "REGISTRY_AND_SHADOW")
                else "REGISTRY"
            ),
            "namedShadowIndexingMode": "ON",
            "filter": {"namedShadowNames": sorted(set(original_named_shadows) | {"$package"})},
        }
        if original_thing_indexing.get("thingConnectivityIndexingMode"):
            new_thing_indexing["thingConnectivityIndexingMode"] = original_thing_indexing[
                "thingConnectivityIndexingMode"
            ]
        if original_thing_indexing.get("customFields"):
            new_thing_indexing["customFields"] = original_thing_indexing["customFields"]

        def _restore_indexing():
            iot.update_indexing_configuration(thingIndexingConfiguration=original_thing_indexing)

        ctx.on_cleanup(_restore_indexing)

        iot.update_indexing_configuration(thingIndexingConfiguration=new_thing_indexing)
        _poll_until(
            lambda: iot.describe_index(indexName="AWS_Things")["indexStatus"],
            lambda status: status == "ACTIVE",
            timeout_s=60.0,
        )

    package_name = ctx.unique_name("sim2real-iot-pkg-")
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

    baseline = iot.get_package(packageName=package_name)
    assert not baseline.get("defaultVersionName"), "package must start with no default version"

    iot.update_package(
        packageName=package_name,
        defaultVersionName=version_name,
        clientToken=str(uuid.uuid4()),
    )

    updated = _poll_until(
        lambda: iot.get_package(packageName=package_name),
        lambda pkg: pkg.get("defaultVersionName") == version_name,
        timeout_s=30.0,
    )
    assert updated["defaultVersionName"] == version_name, (
        f"expected GetPackage.defaultVersionName == {version_name!r}, "
        f"got {updated.get('defaultVersionName')!r}"
    )

    # Account-wide package configuration round trip (restored afterward, since real AWS has
    # no dedicated reset call for this setting). Enabling versionUpdateByJobsConfig requires
    # a role that AWS IoT jobs can assume to update the reserved named shadow.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-pkgcfg-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-behav-pkgcfg-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "iot:UpdateThingShadow", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    previous_config = iot.get_package_configuration().get("versionUpdateByJobsConfig", {})

    def _restore_config():
        iot.update_package_configuration(
            versionUpdateByJobsConfig={"enabled": previous_config.get("enabled", False)},
            clientToken=str(uuid.uuid4()),
        )

    ctx.on_cleanup(_restore_config)

    # A freshly-created role is not always immediately assumable by iot.amazonaws.com, so
    # retry the enable call across a bounded window rather than sleeping blindly.
    def _try_enable():
        try:
            iot.update_package_configuration(
                versionUpdateByJobsConfig={"enabled": True, "roleArn": role_arn},
                clientToken=str(uuid.uuid4()),
            )
            return True
        except ClientError as err:
            if err.response["Error"]["Code"] in ("ValidationException", "InvalidRequestException"):
                return False
            raise

    _poll_until(_try_enable, lambda ok: ok is True, timeout_s=60.0, interval_s=5.0)

    new_config = _poll_until(
        lambda: iot.get_package_configuration().get("versionUpdateByJobsConfig", {}),
        lambda cfg: cfg.get("enabled") is True,
        timeout_s=30.0,
    )
    assert new_config["enabled"] is True, (
        f"expected GetPackageConfiguration.versionUpdateByJobsConfig.enabled == True, "
        f"got {new_config.get('enabled')!r}"
    )
    assert new_config["roleArn"] == role_arn, (
        f"expected GetPackageConfiguration.versionUpdateByJobsConfig.roleArn == {role_arn!r}, "
        f"got {new_config.get('roleArn')!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
