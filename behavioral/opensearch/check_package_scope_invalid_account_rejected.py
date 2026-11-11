"""package-scope-invalid-account-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "package-scope-invalid-account-rejected"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePackageScope rejects a PackageUserList entry that isn't a 12-digit account or GLOBAL
    with the shape-constraint ValidationException, leaving AllowListedUserList unchanged."""
    osv = ctx.client("opensearch")
    package_id = _create_available_package(ctx)

    baseline = _describe_package(osv, package_id).get("AllowListedUserList", [])

    error = _client_error(
        lambda: osv.update_package_scope(
            PackageID=package_id, Operation="ADD", PackageUserList=["not-an-account-id"]
        )
    )
    code = error.get("Code")
    message = error.get("Message", "")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    # Without a package-vending entitlement a well-formed id is refused too, with a different
    # message; shape validation runs first, so the exact message pins the shape rejection.
    expected = (
        "1 validation error detected: Value '[not-an-account-id]' at 'packageUserList' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must have length less than or "
        "equal to 12, Member must have length greater than or equal to 6, Member must satisfy "
        "regular expression pattern: ^[0-9]{12}$|^GLOBAL$]"
    )
    assert message == expected, (
        f"expected the packageUserList shape-constraint message (not an entitlement/authorization "
        f"refusal) {expected!r}, got {message!r}"
    )

    after = _describe_package(osv, package_id).get("AllowListedUserList", [])
    assert after == baseline, (
        f"AllowListedUserList changed after a rejected UpdatePackageScope: "
        f"before={baseline} after={after}"
    )


def _create_available_package(ctx) -> str:
    osv = ctx.client("opensearch")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ospkg-").lower()
    key = "sim2real-dictionary.txt"

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _safe_delete_bucket(s3, bucket, key))
    s3.put_object(Bucket=bucket, Key=key, Body=b"gelato, ice cream, frozen custard\n")
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"es.amazonaws.com"},"Action":"s3:GetObject",'
            f'"Resource":"arn:aws:s3:::{bucket}/{key}"}}]}}'
        ),
    )

    package_name = ctx.unique_name("sim2real-pkg-")
    resp = osv.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
        PackageDescription="sim2real behavioral check dictionary package",
    )
    package_id = resp["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _safe_delete_package(osv, package_id))

    status = _wait_package_status(
        osv, package_id, {"AVAILABLE", "VALIDATION_FAILED", "COPY_FAILED"}, timeout_s=300
    )
    assert status == "AVAILABLE", f"package {package_id} landed in {status!r} instead of AVAILABLE"
    return package_id


def _describe_package(osv, package_id: str) -> dict:
    resp = osv.describe_packages(Filters=[{"Name": "PackageID", "Value": [package_id]}])
    items = resp.get("PackageDetailsList", [])
    assert items, f"DescribePackages returned no entries for {package_id}"
    return items[0]


def _wait_package_status(osv, package_id: str, terminal: set[str], timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_package(osv, package_id)["PackageStatus"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"package {package_id} did not reach {terminal} within {timeout_s}s (last={last})")


def _safe_delete_package(osv, package_id: str) -> None:
    try:
        osv.delete_package(PackageID=package_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_bucket(s3, bucket: str, key: str) -> None:
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _client_error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected UpdatePackageScope to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
