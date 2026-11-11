"""data-plane-package-version-artifact-round-trip."""
from __future__ import annotations

import io
import json
import uuid
import zipfile

from behavioral_harness import tags

CHECK = "data-plane-package-version-artifact-round-trip"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """AssociateSbomWithPackageVersion's S3 location round-trips byte-identical through
    repeated GetPackageVersion calls (bucket/key/version are never dropped, renamed, or
    drifted)."""
    iot = ctx.client("iot")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-iot-sbom-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
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
        ),
    )

    key = "sbom/sim2real-test-sbom.zip"
    sbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": [],
    }
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sbom.cdx.json", json.dumps(sbom_doc))
    put_resp = s3.put_object(Bucket=bucket, Key=key, Body=zip_buf.getvalue(), ContentType="application/zip")
    object_version = put_resp["VersionId"]

    _ensure_package_indexing_active(ctx)

    package_name = ctx.unique_name("sim2real-iot-pkg-")
    version_name = "v1"
    _create_package_retry(iot, package_name)
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))
    iot.create_package_version(packageName=package_name, versionName=version_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: iot.delete_package_version(packageName=package_name, versionName=version_name))

    before = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert "sbom" not in before, f"expected no sbom before association, got {before.get('sbom')!r}"

    associate_resp = _associate_with_retry(
        iot,
        package_name=package_name,
        version_name=version_name,
        bucket=bucket,
        key=key,
        object_version=object_version,
    )
    expected_location = {"bucket": bucket, "key": key, "version": object_version}
    assert associate_resp["sbom"]["s3Location"] == expected_location, (
        f"associate response s3Location mismatch: expected {expected_location}, "
        f"got {associate_resp['sbom'].get('s3Location')!r}"
    )

    got = iot.get_package_version(packageName=package_name, versionName=version_name)
    sbom_location = got["sbom"]["s3Location"]
    assert sbom_location["bucket"] == bucket, f"bucket drifted: expected {bucket!r}, got {sbom_location['bucket']!r}"
    assert sbom_location["key"] == key, f"key drifted: expected {key!r}, got {sbom_location['key']!r}"
    assert sbom_location["version"] == object_version, (
        f"version drifted: expected {object_version!r}, got {sbom_location['version']!r}"
    )

    # A second, independent GetPackageVersion call must keep returning the exact same
    # reference -- it must not drift, get truncated, or fall back to a stale/empty value.
    got_again = iot.get_package_version(packageName=package_name, versionName=version_name)
    sbom_location_again = got_again["sbom"]["s3Location"]
    assert sbom_location_again == sbom_location, (
        f"s3Location changed between two independent GetPackageVersion reads: "
        f"first {sbom_location!r}, second {sbom_location_again!r}"
    )


def _ensure_package_indexing_active(ctx, timeout_s=180.0, interval_s=5.0):
    """CreatePackage rejects with ValidationException("Enable fleet indexing for
    '$package' named shadow.") until fleet indexing is on with that named shadow
    as a data source -- a fresh account has this off, so the check must turn it
    on itself rather than assume some earlier run already did."""
    import time

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
    """CreatePackage can lag fleet indexing becoming ACTIVE by a short propagation window;
    retry on the specific ValidationException it raises."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_package(packageName=package_name, tags={"sim2real": CHECK})
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "fleet indexing" in msg.lower() and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _associate_with_retry(iot, *, package_name, version_name, bucket, key, object_version, timeout_s=60.0):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iot.associate_sbom_with_package_version(
                packageName=package_name,
                versionName=version_name,
                sbom={"s3Location": {"bucket": bucket, "key": key, "version": object_version}},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            last_exc = exc
            time.sleep(5)
    raise last_exc


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_object_versions(Bucket=bucket)
    for obj in resp.get("Versions", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"], VersionId=obj["VersionId"])
    for marker in resp.get("DeleteMarkers", []):
        s3.delete_object(Bucket=bucket, Key=marker["Key"], VersionId=marker["VersionId"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

