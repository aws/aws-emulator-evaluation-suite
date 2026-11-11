"""e2e-package-version-artifact-lifecycle."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-package-version-artifact-lifecycle"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing", "resource:account-singleton:iot-package-configuration")
def run(ctx) -> None:
    """An SBOM associated with a package version reaches validation SUCCEEDED, the version publishes
    to PUBLISHED, and versionUpdateByJobsConfig round-trips through GetPackageConfiguration."""
    iot = ctx.client("iot")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    _ensure_package_shadow_indexing(ctx, iot)

    bucket = ctx.unique_name("sim2real-iot-sbom-")
    _create_versioned_bucket(ctx, s3, bucket, ctx.region)

    key = "sbom.zip"
    version_id = _upload_sbom_zip(s3, bucket, key)

    package_name = ctx.unique_name("sim2real-pkg-")
    version_name = ctx.unique_name("sim2real-ver-")

    iot.create_package(packageName=package_name, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))
    iot.create_package_version(
        packageName=package_name, versionName=version_name, tags={"sim2real": "true"}
    )
    ctx.on_cleanup(lambda: iot.delete_package_version(packageName=package_name, versionName=version_name))

    associate_resp = iot.associate_sbom_with_package_version(
        packageName=package_name,
        versionName=version_name,
        sbom={"s3Location": {"bucket": bucket, "key": key, "version": version_id}},
    )
    assert associate_resp["sbomValidationStatus"] in ("IN_PROGRESS", "SUCCEEDED"), (
        f"expected IN_PROGRESS or SUCCEEDED, got {associate_resp['sbomValidationStatus']!r}"
    )

    # leaves headroom under the 300s check budget for the steps after this poll
    validation_status = _poll_sbom_validation(iot, package_name, version_name, timeout_s=240)
    if validation_status != "SUCCEEDED":
        results = iot.list_sbom_validation_results(
            packageName=package_name, versionName=version_name
        ).get("validationResultSummaries", [])
        detail = "; ".join(
            f"{r.get('fileName')}:{r.get('errorCode')}:{r.get('errorMessage')}" for r in results
        )
        raise AssertionError(f"status={validation_status} detail={detail}"[:300])

    iot.update_package_version(packageName=package_name, versionName=version_name, action="PUBLISH")
    published = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert published["status"] == "PUBLISHED", f"expected PUBLISHED, got {published['status']!r}"

    role_arn = _create_jobs_config_role(ctx, iam)

    client_token = str(uuid.uuid4())
    iot.update_package_configuration(
        versionUpdateByJobsConfig={"enabled": True, "roleArn": role_arn},
        clientToken=client_token,
    )

    config = iot.get_package_configuration()
    got_enabled = config["versionUpdateByJobsConfig"]["enabled"]
    assert got_enabled is True, f"expected versionUpdateByJobsConfig.enabled=True, got {got_enabled!r}"
    got_role_arn = config["versionUpdateByJobsConfig"]["roleArn"]
    assert got_role_arn == role_arn, f"expected roleArn={role_arn!r}, got {got_role_arn!r}"


# ===== helpers =====
def _ensure_package_shadow_indexing(ctx, iot) -> None:
    """Enable fleet indexing of the reserved $package named shadow, which CreatePackage requires,
    and restore the prior account-wide indexing configuration on cleanup."""
    before = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})
    already_on = (
        before.get("namedShadowIndexingMode") == "ON"
        and "$package" in (before.get("filter", {}) or {}).get("namedShadowNames", [])
    )
    if already_on:
        return

    prior_mode = before.get("thingIndexingMode", "OFF")
    prior_filter = before.get("filter", {}) or {}
    prior_named_shadow_mode = before.get("namedShadowIndexingMode", "OFF")
    prior_shadow_names = list(prior_filter.get("namedShadowNames", []))

    new_thing_mode = "REGISTRY" if prior_mode == "OFF" else prior_mode
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": new_thing_mode,
            "namedShadowIndexingMode": "ON",
            "filter": {"namedShadowNames": list(set(prior_shadow_names + ["$package"]))},
        }
    )

    def _restore():
        iot.update_indexing_configuration(
            thingIndexingConfiguration={
                "thingIndexingMode": prior_mode,
                "namedShadowIndexingMode": prior_named_shadow_mode,
                "filter": {"namedShadowNames": prior_shadow_names},
            }
        )

    ctx.on_cleanup(_restore)
    # indexing config changes propagate asynchronously
    _wait_for_shadow_indexing_on(iot, timeout_s=30)


def _wait_for_shadow_indexing_on(iot, timeout_s: float = 30.0) -> None:
    import time as _time

    deadline = _time.monotonic() + timeout_s
    while _time.monotonic() < deadline:
        cfg = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})
        if cfg.get("namedShadowIndexingMode") == "ON" and "$package" in (
            cfg.get("filter", {}) or {}
        ).get("namedShadowNames", []):
            return
        _time.sleep(2)


def _create_versioned_bucket(ctx, s3, bucket: str, region: str) -> None:
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iot.amazonaws.com"},
                "Action": "s3:*",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _upload_sbom_zip(s3, bucket: str, key: str) -> str:
    sbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sbom.json", json.dumps(sbom_doc))
    resp = s3.put_object(
        Bucket=bucket, Key=key, Body=buf.getvalue(), ContentType="application/zip"
    )
    return resp["VersionId"]


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objects = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_sbom_validation(iot, package_name: str, version_name: str, timeout_s: float = 90.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = "IN_PROGRESS"
    while time.monotonic() < deadline:
        resp = iot.get_package_version(packageName=package_name, versionName=version_name)
        status = resp.get("sbomValidationStatus", "IN_PROGRESS")
        if status != "IN_PROGRESS":
            return status
        time.sleep(3)
    return status


def _create_jobs_config_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-pkgcfg-role-")
    trust = {
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
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="update-shadow",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "iot:UpdateThingShadow", "Resource": "*"}
                ],
            }
        ),
    )

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="update-shadow")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
