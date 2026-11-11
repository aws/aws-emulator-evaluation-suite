"""sbom-association-conflict-on-duplicate."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sbom-association-conflict-on-duplicate"
GROUP = "state-machine"
SERVICES = ["iot"]


def _sbom_zip_bytes() -> bytes:
    """AWS IoT SBOMs must be a zip archive containing SPDX/CycloneDX JSON
    file(s)."""
    minimal_sbom = b'{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[]}'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("sbom.json", minimal_sbom)
    return buf.getvalue()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """AssociateSbomWithPackageVersion is an upsert, not a ConflictException: a second, different
    SBOM replaces the version's association (GetPackageVersion reflects the new S3 location), and a
    version with no prior association accepts one in the same run."""
    iot = ctx.client("iot")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-sbom-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    # AssociateSbomWithPackageVersion requires an S3 object VERSION id, so the
    # bucket must have versioning enabled.
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    # AWS IoT (acting as iot.amazonaws.com) must be granted resource-based
    # access to fetch the SBOM zip archive from the bucket.
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "iot.amazonaws.com"},
                    "Action": "s3:*",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ],
        }),
    )

    sbom1_key, sbom2_key, sbom3_key = "sbom1.zip", "sbom2.zip", "sbom3.zip"
    sbom_bytes = _sbom_zip_bytes()
    versions = {}
    for key in (sbom1_key, sbom2_key, sbom3_key):
        versions[key] = s3.put_object(
            Bucket=bucket, Key=key, Body=sbom_bytes, ContentType="application/zip"
        )["VersionId"]

    # The Software Package Catalog requires fleet indexing enabled with the
    # reserved $package named shadow as a data source before CreatePackage
    # will succeed; otherwise it fails with ValidationException "Enable fleet
    # indexing for '$package' named shadow".
    _ensure_package_indexing_active(ctx)

    package_name = ctx.unique_name("sim2real-sbompkg-")
    _create_package_retry(iot, package_name)
    ctx.on_cleanup(lambda: _safe_delete_package(iot, package_name))

    version_name = "v1"
    iot.create_package_version(packageName=package_name, versionName=version_name)
    ctx.on_cleanup(lambda: _safe_delete_version(iot, package_name, version_name))

    first = _associate_sbom_retry(
        iot,
        package_name,
        version_name,
        {"s3Location": {"bucket": bucket, "key": sbom1_key, "version": versions[sbom1_key]}},
    )
    assert first["sbom"]["s3Location"]["key"] == sbom1_key, (
        f"expected the first association's own response to echo {sbom1_key!r}, "
        f"got {first['sbom']['s3Location']['key']!r}"
    )

    # A second, different SBOM association on the SAME package version
    # succeeds -- it is an upsert, not an append-once-and-reject.
    second_on_same = _associate_sbom_retry(
        iot,
        package_name,
        version_name,
        {"s3Location": {"bucket": bucket, "key": sbom2_key, "version": versions[sbom2_key]}},
    )
    assert second_on_same["sbom"]["s3Location"]["key"] == sbom2_key, (
        f"expected the duplicate association's own response to echo {sbom2_key!r} "
        f"(not a ConflictException), got {second_on_same['sbom']['s3Location']['key']!r}"
    )

    # Effect: the association was REPLACED (GetPackageVersion reflects sbom2,
    # not the original sbom1).
    fetched = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert fetched["sbom"]["s3Location"]["key"] == sbom2_key, (
        f"expected GetPackageVersion (independent of the associate call) to reflect "
        f"the replacement {sbom2_key!r}, got {fetched['sbom']['s3Location']['key']!r}"
    )

    # Positive control: a package version with NO prior association accepts one.
    version_name2 = "v2"
    iot.create_package_version(packageName=package_name, versionName=version_name2)
    ctx.on_cleanup(lambda: _safe_delete_version(iot, package_name, version_name2))
    third = _associate_sbom_retry(
        iot,
        package_name,
        version_name2,
        {"s3Location": {"bucket": bucket, "key": sbom3_key, "version": versions[sbom3_key]}},
    )
    assert third["sbom"]["s3Location"]["key"] == sbom3_key, (
        f"expected the fresh association's own response to echo {sbom3_key!r}, "
        f"got {third['sbom']['s3Location']['key']!r}"
    )

    # Terminal assertion is an INDEPENDENT read at the destination, not the
    # mutating associate call's own response.
    fetched2 = iot.get_package_version(packageName=package_name, versionName=version_name2)
    assert fetched2["sbom"]["s3Location"]["key"] == sbom3_key, (
        f"expected GetPackageVersion on the never-before-associated version to "
        f"independently reflect {sbom3_key!r}, got {fetched2['sbom']['s3Location']['key']!r}"
    )


def _ensure_package_indexing_active(ctx, timeout_s=180.0, interval_s=5.0):
    """The Software Package Catalog requires fleet indexing enabled with the reserved
    $package named shadow as a data source before CreatePackage will succeed."""
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
            "thingConnectivityIndexingMode": current.get("thingConnectivityIndexingMode", "OFF"),
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


def _create_package_retry(iot, package_name, timeout_s=120.0, interval_s=5.0):
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
            if (
                code == "ValidationException"
                and "fleet indexing" in msg.lower()
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _associate_sbom_retry(iot, package_name, version_name, sbom, timeout_s=60.0, interval_s=5.0):
    """The just-created S3 bucket policy can take a few seconds to propagate before
    AWS IoT's own read of the SBOM object succeeds; retry on the specific
    ValidationException it raises while access is still propagating."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return iot.associate_sbom_with_package_version(
                packageName=package_name, versionName=version_name, sbom=sbom
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if (
                code == "ValidationException"
                and "not accessible" in msg.lower()
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _safe_delete_version(iot, package_name: str, version_name: str) -> None:
    """Teardown: a missing package version is clean; anything else raises."""
    try:
        iot.delete_package_version(packageName=package_name, versionName=version_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_package(iot, package_name: str) -> None:
    iot.delete_package(packageName=package_name)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_object_versions(Bucket=bucket)
        for obj in resp.get("Versions", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"], VersionId=obj["VersionId"])
        for marker in resp.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=marker["Key"], VersionId=marker["VersionId"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
