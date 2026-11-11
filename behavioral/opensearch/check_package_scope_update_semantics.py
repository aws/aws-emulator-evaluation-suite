"""package-scope-update-semantics."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "package-scope-update-semantics"
GROUP = "state-machine"
SERVICES = ["opensearch"]

_DUMMY_ACCOUNT = "222233334444"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePackageScope ADD and REMOVE on a vending-enabled package are both rejected with the
    same ValidationException: scope management needs an account-level entitlement (an AWS Support
    enrollment) that a freshly provisioned account does not carry."""
    osv = ctx.client("opensearch")
    package_id = _create_available_package(ctx)

    # Positive control: package creation and its read are healthy, so the refusal below is the
    # entitlement gate and not broken credentials.
    before = _describe_package(osv, package_id)
    assert before["PackageStatus"] == "AVAILABLE", before
    assert _DUMMY_ACCOUNT not in before.get("AllowListedUserList", []), before

    add_code, add_message = _error(
        lambda: osv.update_package_scope(
            PackageID=package_id, Operation="ADD", PackageUserList=[_DUMMY_ACCOUNT]
        )
    )
    assert add_code == "ValidationException", (
        f"expected ValidationException rejecting UpdatePackageScope ADD, got {add_code!r}: {add_message!r}"
    )
    assert "not authorized to perform this operation" in add_message, (
        f"expected the package-vending entitlement refusal, got {add_message!r}"
    )

    after_add = _describe_package(osv, package_id)
    assert _DUMMY_ACCOUNT not in after_add.get("AllowListedUserList", []), (
        f"a rejected ADD must not add the account to AllowListedUserList, got {after_add.get('AllowListedUserList')}"
    )

    remove_code, remove_message = _error(
        lambda: osv.update_package_scope(
            PackageID=package_id, Operation="REMOVE", PackageUserList=[_DUMMY_ACCOUNT]
        )
    )
    assert remove_code == "ValidationException", (
        f"expected ValidationException rejecting UpdatePackageScope REMOVE, got {remove_code!r}: {remove_message!r}"
    )
    assert remove_message == add_message, (
        "ADD and REMOVE must be refused identically by the same account-level entitlement gate, "
        f"got add={add_message!r} remove={remove_message!r}"
    )

    after_remove = _describe_package(osv, package_id)
    assert _DUMMY_ACCOUNT not in after_remove.get("AllowListedUserList", []), (
        f"REMOVE must also leave AllowListedUserList unchanged, got {after_remove.get('AllowListedUserList')}"
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
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
        # UpdatePackageScope (used to allow-list other accounts) is only permitted on
        # packages that were created with vending explicitly enabled; otherwise it's
        # rejected with "Operation not allowed. This account is not authorized...".
        PackageVendingOptions={"VendingEnabled": True},
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


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError("expected UpdatePackageScope to be rejected in this account, but it succeeded")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
