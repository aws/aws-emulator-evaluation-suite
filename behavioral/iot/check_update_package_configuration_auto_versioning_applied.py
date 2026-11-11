"""update-package-configuration-auto-versioning-applied."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-package-configuration-auto-versioning-applied"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:iot-indexing", "resource:account-singleton:iot-package-configuration")
def run(ctx) -> None:
    """Re-creating a published package version fails ConflictException with AWS's exact message; with
    versionUpdateByJobsConfig enabled and its roleArn read back, a succeeded job writes the version into the
    thing's reserved "$package" named shadow without the client updating the shadow."""

    iot = ctx.client("iot")
    iam = ctx.client("iam")
    jobs_endpoint = ctx.endpoint_url(iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"])
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=jobs_endpoint)
    data_endpoint = jobs_endpoint
    iot_data = ctx.client("iot-data", endpoint_url=data_endpoint)

    role_name = ctx.unique_name("sim2real-iot-pkgrole-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "iot.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    inline_policy_name = "shadow-update"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "iot:DescribeEndpoint", "Resource": "*"},
                    {
                        "Effect": "Allow",
                        "Action": ["iot:GetThingShadow", "iot:UpdateThingShadow"],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    # CreatePackage requires fleet indexing to be enabled on the reserved "$package" named
    # shadow (Software Package Catalog data source) before any package can be created.
    original_thing_indexing = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})

    def _restore_indexing():
        iot.update_indexing_configuration(thingIndexingConfiguration=original_thing_indexing)

    ctx.on_cleanup(_restore_indexing)

    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": "REGISTRY_AND_SHADOW",
            "namedShadowIndexingMode": "ON",
            "filter": {"namedShadowNames": ["$package"]},
        }
    )
    _poll_until(
        lambda: iot.describe_index(indexName="AWS_Things")["indexStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60.0,
        interval_s=2.0,
    )

    package_name = ctx.unique_name("sim2real-iot-pkg-")
    iot.create_package(packageName=package_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))

    version_name = "1.0.0"
    pv = iot.create_package_version(
        packageName=package_name,
        versionName=version_name,
        tags={"sim2real": CHECK},
    )
    package_version_arn = pv["packageVersionArn"]
    ctx.on_cleanup(lambda: iot.delete_package_version(packageName=package_name, versionName=version_name))
    iot.update_package_version(packageName=package_name, versionName=version_name, action="PUBLISH")

    # Overly-permissive check: re-creating the identical (packageName, versionName) pair
    # must be rejected with ConflictException rather than silently succeeding or
    # returning a second, distinct version.
    dup = _client_error(
        lambda: iot.create_package_version(packageName=package_name, versionName=version_name)
    )
    assert dup["Code"] == "ConflictException", f"expected ConflictException, got {dup!r}"
    expected = (
        f"Conditional check failure: Received duplicate request for package {package_name} "
        f"version {version_name}"
    )
    assert dup["Message"] == expected, f"expected message {expected!r}, got {dup['Message']!r}"

    ctx.on_cleanup(
        lambda: iot.update_package_configuration(
            versionUpdateByJobsConfig={"enabled": False}, clientToken=str(uuid.uuid4())
        )
    )

    # A freshly-created role is not always immediately assumable by iot.amazonaws.com; IoT
    # validates the role at UpdatePackageConfiguration time and rejects it with
    # ValidationException/InvalidRequestException until IAM/STS propagation catches up. Retry
    # across a bounded window rather than sleeping blindly.
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

    cfg = iot.get_package_configuration()["versionUpdateByJobsConfig"]
    assert cfg["enabled"] is True, f"expected versionUpdateByJobsConfig.enabled True, got {cfg['enabled']!r}"
    assert cfg["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {cfg['roleArn']!r}"

    thing_name = ctx.unique_name("sim2real-iot-pkgthing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    job_id = ctx.unique_name("sim2real-iot-pkgjob-")
    iot.create_job(
        jobId=job_id,
        targets=[thing_arn],
        targetSelection="SNAPSHOT",
        document=json.dumps({"operation": "install", "package": package_name}),
        destinationPackageVersions=[package_version_arn],
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_job(jobId=job_id, force=True))

    started = _poll_until(
        lambda: jobs_data.start_next_pending_job_execution(thingName=thing_name),
        lambda r: r.get("execution", {}).get("status") == "IN_PROGRESS",
        timeout_s=60.0,
        interval_s=2.0,
    )
    execution = started["execution"]

    jobs_data.update_job_execution(
        jobId=job_id,
        thingName=thing_name,
        status="SUCCEEDED",
        executionNumber=execution["executionNumber"],
        expectedVersion=execution["versionNumber"],
    )

    def _get_package_shadow():
        try:
            resp = iot_data.get_thing_shadow(thingName=thing_name, shadowName="$package")
            return json.loads(resp["payload"].read())
        except iot_data.exceptions.ResourceNotFoundException:
            return None

    shadow = _poll_until(
        _get_package_shadow,
        lambda doc: doc is not None and package_name in doc.get("state", {}).get("reported", {}),
        timeout_s=180.0,
        interval_s=5.0,
    )
    reported_version = shadow["state"]["reported"][package_name]["version"]
    assert reported_version == version_name, (
        f"expected the $package shadow to report version {version_name!r} for {package_name!r}, "
        f"got {reported_version!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
