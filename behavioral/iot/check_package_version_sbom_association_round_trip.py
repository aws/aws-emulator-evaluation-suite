"""package-version-sbom-association-round-trip."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "package-version-sbom-association-round-trip"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """SBOM metadata attached via AssociateSbomWithPackageVersion is returned
    byte-identical (same bucket/key/version) on a subsequent GetPackageVersion, and a
    validation status is populated as a result of the association."""
    iot = ctx.client("iot")
    s3 = ctx.client("s3")
    _ensure_package_indexing_active(ctx)
    package_name = ctx.unique_name("sim2real-pkg-sbom-")
    _create_package_retry(iot, package_name)
    ctx.on_cleanup(lambda: _delete_package_quiet(ctx, package_name))

    version_name = "v1"
    iot.create_package_version(packageName=package_name, versionName=version_name)
    ctx.on_cleanup(
        lambda: _delete_package_version_quiet(ctx, package_name, version_name)
    )

    before = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert "sbom" not in before

    bucket_name = ctx.unique_name("sim2real-sbom-bucket-")
    region = s3.meta.region_name
    if region and region != "us-east-1":
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    else:
        s3.create_bucket(Bucket=bucket_name)
    ctx.on_cleanup(lambda: _delete_bucket_quiet(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    s3.put_bucket_versioning(
        Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
    )
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "iot.amazonaws.com"},
                        "Action": "s3:*",
                        "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    }
                ],
            }
        ),
    )

    key = "app-v1.zip"
    zip_bytes = _build_sbom_zip()
    put_response = s3.put_object(
        Bucket=bucket_name, Key=key, Body=zip_bytes, ContentType="application/zip"
    )
    object_version = put_response["VersionId"]

    sbom = {
        "s3Location": {
            "bucket": bucket_name,
            "key": key,
            "version": object_version,
        }
    }
    associate_response = _associate_sbom_retry(iot, package_name, version_name, sbom)
    assert associate_response["sbom"] == sbom

    described = iot.get_package_version(
        packageName=package_name, versionName=version_name
    )
    assert described["sbom"] == sbom
    assert described["sbom"]["s3Location"]["bucket"] == sbom["s3Location"]["bucket"]
    assert described["sbom"]["s3Location"]["key"] == sbom["s3Location"]["key"]
    assert described["sbom"]["s3Location"]["version"] == sbom["s3Location"]["version"]

    # Validation is asynchronous: right after association it is IN_PROGRESS, or already
    # SUCCEEDED on a target that validates a trivial SPDX doc before the read.
    assert described["sbomValidationStatus"] in ("IN_PROGRESS", "SUCCEEDED"), (
        f"expected the just-associated SBOM to be validating or validated, got "
        f"sbomValidationStatus={described['sbomValidationStatus']!r}"
    )
    # Validation then settles: poll GetPackageVersion until sbomValidationStatus leaves
    # IN_PROGRESS, and grade the terminal status.
    final = _poll_until(
        lambda: iot.get_package_version(packageName=package_name, versionName=version_name),
        lambda d: d.get("sbomValidationStatus") in ("SUCCEEDED", "FAILED"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final["sbomValidationStatus"] == "SUCCEEDED", (
        f"expected the associated SBOM to validate, got "
        f"sbomValidationStatus={final['sbomValidationStatus']!r}"
    )
    assert final["sbom"] == sbom, f"expected the SBOM location to survive validation, got {final['sbom']!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _build_sbom_zip() -> bytes:
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "sim2real-behavioral-sbom",
        "documentNamespace": "https://example.com/sim2real-behavioral-sbom",
        "creationInfo": {
            "creators": ["Tool: sim2real-behavioral-suite"],
            "created": "2024-01-01T00:00:00Z",
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-app",
                "name": "sim2real-app",
                "versionInfo": "1.0.0",
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        ],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sbom.spdx.json", json.dumps(spdx_doc))
    return buf.getvalue()


def _associate_sbom_retry(iot, package_name, version_name, sbom, timeout_s=60.0, interval_s=5.0):
    """The just-created S3 bucket policy can take a few seconds to propagate before
    AWS IoT's own read of the SBOM object succeeds; retry on the specific
    ValidationException it raises while access is still propagating."""
    from botocore.exceptions import ClientError

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


def _delete_package_version_quiet(ctx, package_name, version_name):
    """Teardown: delete one package version; a missing version is clean, anything else raises."""
    iot = ctx.client("iot")
    try:
        iot.delete_package_version(packageName=package_name, versionName=version_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_package_quiet(ctx, package_name):
    iot = ctx.client("iot")
    iot.delete_package(packageName=package_name)


def _delete_bucket_quiet(ctx, bucket_name):
    s3 = ctx.client("s3")
    try:
        versions = s3.list_object_versions(Bucket=bucket_name)
        objects = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
        ]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _ensure_package_indexing_active(ctx, timeout_s=180.0, interval_s=5.0):
    """The Software Package Catalog requires fleet indexing enabled with the reserved
    $package named shadow as a data source before CreatePackage will succeed. The
    account's original indexing configuration is restored at cleanup."""
    iot = ctx.client("iot")
    current = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})
    ctx.on_cleanup(lambda: iot.update_indexing_configuration(thingIndexingConfiguration=current))
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
        iot.update_indexing_configuration(thingIndexingConfiguration=new_cfg)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = iot.describe_index(indexName="AWS_Things")["indexStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError("AWS_Things index never reached ACTIVE within timeout")


def _create_package_retry(iot, package_name, timeout_s=120.0, interval_s=5.0):
    """CreatePackage can lag fleet indexing becoming ACTIVE by a short propagation window;
    retry on the specific ValidationException it raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_package(
                packageName=package_name,
                tags={"sim2real": CHECK},
            )
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
