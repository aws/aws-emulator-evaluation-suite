"""update-package-invalid-version-format-base-exception."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-package-invalid-version-format-base-exception"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePackage rejects a version-shaped PackageID violating the PackageID pattern with a
    ValidationException, leaves the real package untouched, and the same call against the real
    PackageID succeeds and ends AVAILABLE."""
    client = ctx.client("opensearch")
    package_id, bucket, key = _create_package_with_source(ctx)

    malformed_id = "1.2.3-beta"  # looks like a version string; matches neither PackageID shape
    code, message = _error_detail(
        lambda: client.update_package(
            PackageID=malformed_id,
            PackageSource={"S3BucketName": bucket, "S3Key": key},
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a version-shaped PackageID, got {code!r}"
    )
    expected = (
        f"1 validation error detected: Value '{malformed_id}' at 'packageID' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: ^([FG][0-9]+)$|^(pkg-[a-f0-9]+)$"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


    # Effect absent: the real package's metadata must be untouched by the failed call.
    before = client.describe_packages(
        Filters=[{"Name": "PackageID", "Value": [package_id]}]
    )["PackageDetailsList"][0]
    assert before["PackageID"] == package_id, (
        f"expected the untouched package {package_id!r} in the independent read, "
        f"got {before['PackageID']!r}"
    )

    # Positive control: the identical call shape against the REAL PackageID (and a real,
    # accessible S3 source) is accepted and actually completes.
    resp = client.update_package(
        PackageID=package_id,
        PackageSource={"S3BucketName": bucket, "S3Key": key},
        CommitMessage="sim2real-real-update",
    )
    assert resp["PackageDetails"]["PackageID"] == package_id, (
        f"expected the positive control to update {package_id!r}, "
        f"got {resp['PackageDetails']['PackageID']!r}"
    )

    terminal = _poll_until(
        lambda: client.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"][0]["PackageStatus"],
        lambda status: status not in ("COPYING", "VALIDATING"),
        timeout_s=120,
        interval_s=3,
    )
    assert terminal == "AVAILABLE", (
        f"expected the update against a real, accessible S3 object to end AVAILABLE, got "
        f"{terminal!r}"
    )

def _error_detail(fn):
    """Call fn() and return its botocore error (code, message); an unexpected success fails."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s (last value={value!r})")


def _create_package_with_source(ctx):
    """Create a real S3 bucket + object and a package backed by it. CreatePackage validates
    S3 accessibility synchronously, so a nonexistent bucket/key would be rejected up front
    rather than accepted.
    """
    s3 = ctx.client("s3")
    client = ctx.client("opensearch")
    bucket = ctx.unique_name("sim2real-pkgbucket-")
    key = "dictionary.txt"

    if ctx.region == "us-east-1":
        # S3's own CreateBucket contract: LocationConstraint is invalid for us-east-1.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real\n")

    name = ctx.unique_name("sim2real-pkg-")
    resp = client.create_package(
        PackageName=name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )
    package_id = resp["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: client.delete_package(PackageID=package_id))

    deadline = time.monotonic() + 120
    status = None
    while time.monotonic() < deadline:
        status = client.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"][0]["PackageStatus"]
        if status not in ("COPYING", "VALIDATING"):
            break
        time.sleep(3)
    assert status == "AVAILABLE", f"package {package_id} did not become AVAILABLE: {status!r}"
    return package_id, bucket, key


def _delete_bucket(s3, bucket):
    try:
        objs = s3.list_object_versions(Bucket=bucket)
        to_delete = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in objs.get("Versions", [])]
        to_delete += [
            {"Key": o["Key"], "VersionId": o["VersionId"]} for o in objs.get("DeleteMarkers", [])
        ]
        if to_delete:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": to_delete}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        else:
            for o in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
