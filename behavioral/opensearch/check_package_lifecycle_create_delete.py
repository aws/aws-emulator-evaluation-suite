"""package-lifecycle-create-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "package-lifecycle-create-delete"
GROUP = 'package'
SERVICES = ['opensearch']

def _create_test_package(ctx) -> tuple[str, dict]:
    """Create a TXT-DICTIONARY package backed by a real S3 object so package
    validation (which real AWS performs) succeeds deterministically.

    An OpenSearch package cannot exist without an S3 source. If the execution
    role cannot create the staging bucket, that is a missing prerequisite, not
    a fidelity signal -- fail with a message naming the missing permission
    rather than reporting a generic assertion failure.
    """
    os = ctx.client("opensearch")
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-os-pkg-")
    region = ctx.region
    try:
        # S3's CreateBucket rejects an explicit LocationConstraint of us-east-1
        # (its own default region) -- this is a transport-only branch, not a
        # region pin: `region` still comes from ctx.region.
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
            )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("AccessDenied", "AccessDeniedException", "AllAccessDisabled"):
            raise AssertionError(
                "cannot stage an S3 package source: the execution role lacks "
                f"s3:CreateBucket ({code}). OpenSearch packages require an S3 object, "
                "so the package data-plane cannot be exercised in this account."
            ) from exc
        raise

    def _cleanup_bucket(b=bucket_name):
        for obj in s3.list_objects_v2(Bucket=b).get("Contents", []):
            s3.delete_object(Bucket=b, Key=obj["Key"])
        s3.delete_bucket(Bucket=b)
        try:
            s3.head_bucket(Bucket=b)
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status == 404:
                return
            raise
        raise AssertionError(f"staging bucket {b} still exists after DeleteBucket")

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    key = "dictionary.txt"
    s3.put_object(Bucket=bucket_name, Key=key, Body=b"hello\nworld\n")

    package_name = ctx.unique_name("sim2real-behav-pkg-")

    # A brand-new bucket is not always immediately reachable from the OpenSearch
    # service: CreatePackage then rejects the source with a ValidationException
    # ("Package file not accessible ... S3 bucket is present in the same region")
    # even though the bucket IS in-region and the object IS present. This is pure
    # cross-service S3 propagation latency (max_attempts=1, so there is no built-in
    # retry). Poll CreatePackage until the source resolves.
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = os.create_package(
                PackageName=package_name,
                PackageType="TXT-DICTIONARY",
                PackageSource={"S3BucketName": bucket_name, "S3Key": key},
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if code == "ValidationException" and "not accessible" in msg and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    package_id = resp["PackageDetails"]["PackageID"]

    def _cleanup_package(pid=package_id):
        # dissociate from every domain before deleting (real-AWS ordering). A package the body
        # already deleted answers ValidationException (OpenSearch's not-found for a PackageID);
        # every other error raises so a leftover package is reported.
        try:
            r = os.list_domains_for_package(PackageID=pid)
            for detail in r.get("DomainPackageDetailsList", []):
                os.dissociate_package(PackageID=pid, DomainName=detail["DomainName"])
            os.delete_package(PackageID=pid)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise

    ctx.on_cleanup(_cleanup_package)
    return package_id, {"S3BucketName": bucket_name, "S3Key": key}

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePackage reaches a terminal AVAILABLE status and DeletePackage removes it."""
    os = ctx.client("opensearch")
    package_id, package_source = _create_test_package(ctx)

    def _pkg_status():
        resp = os.describe_packages(Filters=[{"Name": "PackageID", "Value": [package_id]}])
        details = resp.get("PackageDetailsList", [])
        return details[0]["PackageStatus"] if details else None

    def _await_available(what):
        # wait until the package reaches a terminal status
        deadline = time.monotonic() + 180
        status = None
        while time.monotonic() < deadline:
            status = _pkg_status()
            if status in {"AVAILABLE", "VALIDATION_FAILED", "COPY_FAILED"}:
                break
            time.sleep(3)
        else:
            raise AssertionError(f"{what}: package status not met within 180s. Last result: {status!r}")
        assert status == "AVAILABLE", f"{what}: expected package to become AVAILABLE, got {status}"

    _await_available("CreatePackage")

    listed = os.describe_packages(Filters=[{"Name": "PackageID", "Value": [package_id]}])
    listed_id = listed["PackageDetailsList"][0]["PackageID"]
    assert listed_id == package_id, f"expected {package_id} in an independent describe_packages read, got {listed_id}"

    # Positive control: the same calls the gone beats refuse succeed on the live package, so a
    # post-delete refusal means "deleted", not "malformed request".
    history = os.get_package_version_history(PackageID=package_id)
    assert history.get("PackageID") == package_id, (
        f"GetPackageVersionHistory on the live package: expected PackageID {package_id!r}, "
        f"got {history.get('PackageID')!r}"
    )
    updated = os.update_package(PackageID=package_id, PackageSource=package_source)
    updated_id = updated.get("PackageDetails", {}).get("PackageID")
    assert updated_id == package_id, (
        f"UpdatePackage on the live package: expected PackageID {package_id!r}, got {updated_id!r}"
    )
    _await_available("UpdatePackage")

    os.delete_package(PackageID=package_id)
    # Gone 2: DescribePackages filtered to the id stops returning it (real AWS keeps no DELETED
    # row); polled because the delete is asynchronous, DELETE_FAILED ends the wait as a failure.
    _deadline = time.monotonic() + 120
    deleted_status = "?"
    while time.monotonic() < _deadline:
        deleted_status = _pkg_status()
        if deleted_status in (None, "DELETE_FAILED"):
            break
        time.sleep(3)
    else:
        raise AssertionError("package still listed 120s after DeletePackage: " + repr(deleted_status))
    assert deleted_status is None, f"package should be absent from DescribePackages, got {deleted_status}"

    def _refusal(label, fn):
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            return err.get("Code"), status, err.get("Message", "") or ""
        raise AssertionError(f"{label} on the deleted PackageID should fail, but it succeeded")

    # Gone 1: the by-id read answers not-found. Real AWS reports a deleted PackageID as a
    # ValidationException (400) whose message does not name the id.
    code, status, msg = _refusal(
        "GetPackageVersionHistory", lambda: os.get_package_version_history(PackageID=package_id)
    )
    assert code == "ValidationException" and status == 400 and msg, (
        f"GetPackageVersionHistory on deleted package: expected ValidationException/400 with a "
        f"message, got code={code!r} status={status} msg={msg!r}"
    )
    expected_message = "Package not found."
    assert msg == expected_message, f"expected the message {expected_message!r}, got {msg!r}"

    # Gone 3: the dead id is unusable for mutation, not merely unlisted.
    code, status, msg = _refusal("DeletePackage", lambda: os.delete_package(PackageID=package_id))
    assert code == "ValidationException" and status == 400 and msg, (
        f"DeletePackage on deleted package: expected ValidationException/400 with a message, "
        f"got code={code!r} status={status} msg={msg!r}"
    )
    expected_message = "Package not found."
    assert msg == expected_message, f"expected the message {expected_message!r}, got {msg!r}"
    code, status, msg = _refusal(
        "UpdatePackage",
        lambda: os.update_package(PackageID=package_id, PackageSource=package_source),
    )
    assert code == "ValidationException" and status == 400 and msg, (
        f"UpdatePackage on deleted package: expected ValidationException/400 with a message, "
        f"got code={code!r} status={status} msg={msg!r}"
    )
    expected_message = "Package not found."
    assert msg == expected_message, f"expected the message {expected_message!r}, got {msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
