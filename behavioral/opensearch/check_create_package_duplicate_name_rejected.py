"""create-package-duplicate-name-rejected."""
from __future__ import annotations

import time
import uuid
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-package-duplicate-name-rejected"
GROUP = "e2e"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePackage with an existing name fails with BaseException "Package is already in desired state"
    and leaves only the original package; a new name succeeds and its unicode PackageDescription
    survives the DescribePackages round trip.
    """
    s3 = ctx.client("s3")
    opensearch = ctx.client("opensearch")

    bucket = ctx.unique_name("sim2real-osdpkgdup-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="synonyms.txt", Body=b"danish, croissant, pastry\n")

    package_name = _short_name("sim2dup-")
    first = opensearch.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": "synonyms.txt"},
    )["PackageDetails"]
    first_id = first["PackageID"]
    ctx.on_cleanup(lambda: opensearch.delete_package(PackageID=first_id))
    # Let the first package settle, so the duplicate is refused for its NAME and not for the
    # first package's in-flight validation.
    _wait_package_available(opensearch, first_id)

    def _create_duplicate():
        resp = opensearch.create_package(
            PackageName=package_name,
            PackageType="TXT-DICTIONARY",
            PackageSource={"S3BucketName": bucket, "S3Key": "synonyms.txt"},
        )
        dup_id = resp["PackageDetails"]["PackageID"]
        ctx.on_cleanup(lambda: opensearch.delete_package(PackageID=dup_id))
        return resp

    refusal = _error(_create_duplicate)
    # Empirically, real OpenSearch Service returns BaseException (400) for a duplicate
    # PackageName, not the documented ResourceAlreadyExistsException (409) — the ground
    # truth here is the live API's behavior, not the API reference doc.
    assert refusal == ("BaseException", "Package is already in desired state"), (
        f"expected BaseException with AWS's exact duplicate-name message, got {refusal!r}"
    )

    matching = opensearch.describe_packages(
        Filters=[{"Name": "PackageName", "Value": [package_name]}]
    )["PackageDetailsList"]
    assert len(matching) == 1
    assert matching[0]["PackageID"] == first_id

    # Positive control: a genuinely different name is unaffected by the rejection above.
    # It also carries a PackageDescription with unicode + special characters, to check
    # that value round-trips through CreatePackage -> DescribePackages unchanged.
    other_name = _short_name("sim2dupctl-")
    description = "caf\u00e9 \u4e2d\u6587 \u2603 quotes\"'&<>/=:sim2real"
    second = opensearch.create_package(
        PackageName=other_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": "synonyms.txt"},
        PackageDescription=description,
    )["PackageDetails"]
    second_id = second["PackageID"]
    ctx.on_cleanup(lambda: opensearch.delete_package(PackageID=second_id))
    assert second["PackageName"] == other_name
    assert second_id != first_id
    assert second["PackageDescription"] == description

    # Representation: the exact unicode/special-character description survives an
    # independent read-back via DescribePackages, not just the create response echo.
    reread = opensearch.describe_packages(
        Filters=[{"Name": "PackageID", "Value": [second_id]}]
    )["PackageDetailsList"]
    assert len(reread) == 1
    assert reread[0]["PackageDescription"] == description


def _wait_package_available(opensearch, package_id: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        details = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"]
        status = details[0]["PackageStatus"] if details else None
        if status == "AVAILABLE":
            return
        if status in ("COPY_FAILED", "VALIDATION_FAILED", "DELETE_FAILED"):
            raise AssertionError(f"package {package_id} settled in {status}, not AVAILABLE")
        time.sleep(5.0)
    raise AssertionError(f"package {package_id} not AVAILABLE within {timeout_s}s (last {status!r})")


def _short_name(prefix: str, maxlen: int = 28) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"[:maxlen]


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so an emulator accepting what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
